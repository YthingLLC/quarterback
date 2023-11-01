#![warn(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::RwLock;
use std::time::Duration;
//maybe I will use this if I ever care about supporting Windows
//use std::path::Path;

use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::prelude::*;
use clap::{Parser, ValueEnum};
use indoc::printdoc;
use poem::{http, listener::TcpListener, Route, Server};
use poem_openapi::{param::Path, payload::PlainText, OpenApi, OpenApiService};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use simple_repl::{repl, EvalResult};
use uuid::Uuid;

macro_rules! print_if {
    ($should_print:expr, $($arg:tt)*) => {
        if $should_print {
            println!($($arg)*);
        }
    }
}

macro_rules! parseuuid {
    ($uuid_str:expr, $err:literal) => {
        match Uuid::try_parse($uuid_str) {
            Ok(uuid) => uuid,
            Err(e) => {
                println!("Unable to parse {}: {e}", $err);
                return;
            }
        }
    };
}

macro_rules! getusermut {
    ($self:ident, $uuid:expr) => {
        match $self.users.get_mut($uuid) {
            None => {
                println!("User {} not found.", $uuid.to_string());
                return;
            }
            Some(user) => user,
        }
    };
}

macro_rules! getuser {
    ($self:ident, $uuid:expr) => {
        match $self.users.get($uuid) {
            None => {
                println!("User {} not found.", $uuid.to_string());
                return;
            }
            Some(user) => user,
        }
    };
}

macro_rules! getactionmut {
    ($self:ident, $uuid:expr) => {
        match $self.actions.get_mut($uuid) {
            None => {
                println!("Action {} not found", $uuid.to_string());
                return;
            }
            Some(action) => action,
        }
    };
}

macro_rules! getaction {
    ($self:ident, $uuid:expr) => {
        match $self.actions.get($uuid) {
            None => {
                println!("Action {} not found", $uuid.to_string());
                return;
            }
            Some(action) => action,
        }
    };
}

macro_rules! getrolemut {
    ($self:ident, $uuid:expr) => {
        match $self.roles.get_mut($uuid) {
            None => {
                println!("Role {} not found", $uuid.to_string());
                return;
            }
            Some(role) => role,
        }
    };
}

macro_rules! getrole {
    ($self:ident, $uuid:expr) => {
        match $self.roles.get($uuid) {
            None => {
                println!("Role {} not found", $uuid.to_string());
                return;
            }
            Some(role) => role,
        }
    };
}

//this should always contain a valid argon2 hash
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PasswordString(String);

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackUser {
    user_name: String,
    user_key: PasswordString,
    //If true this user can do anything with no restrictions
    //i.e. roles are not enforced
    super_user: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackRole {
    role_name: String,
    allowed_actions: HashSet<Uuid>,
    allowed_users: HashSet<Uuid>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct QuarterbackAction {
    name: String,
    action_path: String,
    action_args: String,
    timeout: Duration,
    cooldown: Duration,
    signal: u8,
    log_stdout: bool,
}

impl QuarterbackAction {
    fn arg_split(&self) -> Option<std::str::Split<'_, char>> {
        if !self.action_args.is_empty() {
            Some(self.action_args.split(' '))
        } else {
            None
        }
    }

    pub fn execute_sync(&self) -> Option<String> {
        let mut command = std::process::Command::new(&self.action_path);
        if let Some(args) = self.arg_split() {
            command.args(args);
        }

        let mut ret = String::new();
        if self.log_stdout {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
            //TODO: Add an error return to this
            command.spawn().ok()?;
            let output = command.output().ok()?;
            let stderr = &output.stderr;
            let stdout = &output.stdout;

            ret += &format!("{:=^80}\n", format!("Execution Log: {}", Utc::now()));

            ret += &format!("{:=^80}\n", "stderr");
            ret += &format!("{}\n", String::from_utf8_lossy(stderr));

            ret += &format!("{:=^80}\n", "stdout");
            ret += &format!("{}\n", String::from_utf8_lossy(stdout));

            Some(ret)
        } else {
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());

            command.spawn().ok()?;

            ret += &format!(
                "{:=^80}\n{:=^80}",
                "Output Logging Disabled",
                format!("Last Run: {}", Utc::now())
            );
            Some(ret)
        }
    }

    //TODO add cancellation token return
    pub async fn execute(&self) -> Option<String> {
        let mut cmd = tokio::process::Command::new(&self.action_path);

        if let Some(args) = self.arg_split() {
            cmd.args(args);
        }

        if self.log_stdout {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        } else {
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
        }

        let mut child = cmd.spawn().ok()?;
        let mut ret = String::new();

        if self.log_stdout {
            let stdout = child.stdout.take()?;
            let stderr = child.stderr.take()?;

            use tokio::io::AsyncBufReadExt;

            let mut stdout = tokio::io::BufReader::new(stdout).lines();
            let mut stderr = tokio::io::BufReader::new(stderr).lines();

            ret += &format!("{:=^80}\n", format!("Execution Log: {}", Utc::now()));

            while let Some(line) = stderr.next_line().await.ok()? {
                ret += &format!("ERR: {}\n", line);
            }

            while let Some(line) = stdout.next_line().await.ok()? {
                ret += &format!("OUT: {}\n", line);
            }
            ret += &format!("\n{:=^80}", format!("Action Complete: {}", Utc::now()));
        } else {
            let status = child.wait().await.ok()?;
            ret += &format!(
                "{:=^80}\n{:=^80}\n{:=^80}",
                "Output Logging Disabled",
                format!("Last Run: {}", Utc::now()),
                format!("Exit Code: {}", status)
            );
        }

        Some(ret)
    }
}

//TODO: For Daemon mode
#[derive(Debug)]
struct QuarterbackActionUsers {
    //<Action, HashSet<User>>
    //TODO: Convert all Uuid typerefs to struct WhatKindIsIt(Uuid)
    //at runtime map all actions to their allowed users
    //iterate through all roles by action uuid
    //insert action uuid, and the set of allowed users
    //appending to the set of allowed users
    map: HashMap<Uuid, HashSet<Uuid>>,
}

impl QuarterbackUser {
    pub fn check_key(&self, key: &str) -> bool {
        self.check_key_print(key, false)
    }
    fn check_key_print(&self, key: &str, print: bool) -> bool {
        let user_key = match argon2::PasswordHash::new(&self.user_key.0) {
            Err(e) => {
                print_if!(
                    print,
                    "ERROR: {e}; Invalid password string for user: {:?}",
                    self.user_key
                );
                return false;
            }
            Ok(user_key) => user_key,
        };
        match Argon2::default().verify_password(key.as_bytes(), &user_key) {
            Err(_) => {
                print_if!(print, "Invalid key");
                false
            }
            Ok(_) => {
                print_if!(print, "Valid key");
                true
            }
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum QuarterbackConfigBacking {
    Memory,
    YamlFile(YamlFileConfig),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct YamlFileConfig {
    #[serde(skip)]
    config_file_path: String,
}

impl Default for YamlFileConfig {
    fn default() -> Self {
        YamlFileConfig::new()
    }
}

impl YamlFileConfig {
    fn new() -> Self {
        YamlFileConfig {
            config_file_path: String::new(),
        }
    }

    fn set_path(&mut self, path: &str) {
        self.config_file_path = path.to_string();
    }
}

impl QuarterbackConfigBacking {
    fn from_str(s: &str) -> QuarterbackConfigBacking {
        match s {
            "memory" | "m" => QuarterbackConfigBacking::Memory,
            "yaml" | "yml" => QuarterbackConfigBacking::YamlFile(YamlFileConfig::new()),
            _ => QuarterbackConfigBacking::Memory,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackConfig {
    backing: QuarterbackConfigBacking,
    users: HashMap<Uuid, QuarterbackUser>,
    roles: HashMap<Uuid, QuarterbackRole>,
    actions: HashMap<Uuid, QuarterbackAction>,
}

#[derive(Debug)]
enum QuarterbackError {
    HashError(argon2::password_hash::Error),
}

impl Default for QuarterbackConfig {
    fn default() -> Self {
        QuarterbackConfig::new()
    }
}

impl QuarterbackConfig {
    pub fn new() -> QuarterbackConfig {
        QuarterbackConfig {
            backing: QuarterbackConfigBacking::Memory,
            users: HashMap::new(),
            roles: HashMap::new(),
            actions: HashMap::new(),
        }
    }

    pub fn from_yaml(config: &str) -> Result<QuarterbackConfig, serde_yaml::Error> {
        serde_yaml::from_str(config)
    }

    pub fn from_yaml_file_path(file_path: &str) -> Option<QuarterbackConfig> {
        let mut file = File::open(file_path);
        match &mut file {
            Err(e) => {
                eprintln!("Failed to load file: {file_path} - {e}");
                None
            }
            Ok(file) => {
                let yaml_config = QuarterbackConfig::from_yaml_file_handle(file);
                match yaml_config {
                    Err(e) => {
                        eprintln!("Failed to load yaml: {e}");
                        None
                    }

                    Ok(mut conf) => {
                        let cfg = YamlFileConfig {
                            config_file_path: file_path.to_string(),
                        };
                        conf.backing = QuarterbackConfigBacking::YamlFile(cfg);
                        Some(conf)
                    }
                }
            }
        }
    }

    pub fn from_yaml_file_handle(file: &mut File) -> Result<QuarterbackConfig, serde_yaml::Error> {
        let mut conf_string = String::new();
        let _ = file.read_to_string(&mut conf_string);
        QuarterbackConfig::from_yaml(&conf_string)
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self)
    }

    fn save(&self) {
        let yaml = self.to_yaml();
        match yaml {
            Ok(yaml) => match &self.backing {
                QuarterbackConfigBacking::Memory => {
                    println!("{yaml}");
                }
                QuarterbackConfigBacking::YamlFile(file) => {
                    //TODO: Add this to the deuglification pile
                    println!("Saving to {}", file.config_file_path);
                    match File::create(&file.config_file_path) {
                        Err(e) => {
                            println!("ERROR: unable to create file: {}", file.config_file_path);
                            println!("{e}");
                        }
                        Ok(file) => match self.to_yaml() {
                            Err(e) => {
                                println!("ERROR: Unable to create yaml of config: {e}");
                            }
                            Ok(yaml) => {
                                let mut file = file;
                                match file.write_all(yaml.as_bytes()) {
                                    Err(e) => {
                                        println!("ERROR: Unable to write file: {e}");
                                    }
                                    Ok(_) => match file.sync_all() {
                                        Err(e) => println!("ERROR: Can not sync to disk: {e}"),
                                        Ok(_) => println!("SUCCESS: File saved to disk"),
                                    },
                                }
                            }
                        },
                    };
                }
            },
            Err(e) => println!("ERROR: Unable to save: {e}"),
        }
    }

    fn backing(&mut self, iter: &mut core::str::Split<'_, char>) {
        let backing = iter.next();
        if let Some(backing) = backing {
            self.backing = QuarterbackConfigBacking::from_str(backing);
            match &mut self.backing {
                QuarterbackConfigBacking::Memory => {
                    println!("WARNING: Memory should be used for testing only. Configuration is not persisted to disk. `save` command will output to stdout.");
                }
                QuarterbackConfigBacking::YamlFile(config) => {
                    let path = iter.next();
                    if let Some(path) = path {
                        config.set_path(path);
                        println!("Path to config: {}", config.config_file_path);
                    } else {
                        config.set_path("/root/qbconfig.yml");
                        println!("Using default path: {}", config.config_file_path);
                    }
                }
            }
            println!("Backing Set: {:?}", self.backing);
        } else {
            println!("Current Backing: {:?}", self.backing);
            println!();
            println!("To set a new backing:");
            println!("    backing memory");
            println!("    backing yaml /path/to/config.yml <-- defaults to /root/qbconfig.yml if a path is not provided.");
            //println!("ERROR: Missing backing type. Allowed backings: memory, yaml");
        }
    }

    fn print_user(&self, userid: &str) {
        let uuid = parseuuid!(userid, "user id");

        let user = getuser!(self, &uuid);

        println!("      User ID: {}", userid);
        println!("    User Name: {}", user.user_name);
        println!("User Key Hash: {}", user.user_key.0);
        println!("   Super User: {:?}", user.super_user);
    }

    fn print_users(&self) {
        if self.users.is_empty() {
            println!("NO USERS DEFINED");
            return;
        }
        println!("Users");
        println!();
        println!("{:<40} {:<20} Super User", "ID", "Name");
        println!();
        for (id, user) in &self.users {
            println!(
                "{:<40} {:<20} {:?}",
                id.to_string(),
                user.user_name,
                user.super_user
            );
        }
    }

    fn add_user(&mut self, name: &str, super_user: bool) {
        let user_id = Uuid::new_v4();
        let user_name = name.to_string();
        let key = Uuid::new_v4().to_string();
        println!("User Config:");
        println!("ID: {user_id}");
        println!("Name: {user_name}");
        println!("Key: {key} -- SAVE THIS KEY. IT WILL NEVER BE DISPLAYED AGAIN.");
        if super_user {
            println!("Super User: true");
        }

        let key = QuarterbackConfig::hash(&key);
        match key {
            Ok(user_key) => {
                self.users.insert(
                    user_id,
                    QuarterbackUser {
                        user_name,
                        user_key,
                        super_user,
                    },
                );
            }
            Err(e) => {
                println!("Error creating user: {e:?}");
            }
        }
    }

    fn reset_user_key(&mut self, userid: &str, key: &str) {
        let uuid = parseuuid!(userid, "user id");

        let user = getusermut!(self, &uuid);

        match QuarterbackConfig::hash(key) {
            Err(e) => println!("Password hashing failed: {e:?}"),
            Ok(key) => {
                println!("User key updated");
                user.user_key = key;
            }
        }
    }

    //Interactive
    fn check_user_key(&self, userid: &str, key: &str) {
        let uuid = parseuuid!(userid, "user id");

        let user = getuser!(self, &uuid);

        user.check_key_print(key, true);
    }

    //External use
    pub fn check_user_key_from_str(&self, userid: &str, key: &str) -> bool {
        let uuid = Uuid::try_parse(userid);

        if let Ok(uuid) = uuid {
            if let Some(user) = self.users.get(&uuid) {
                return user.check_key(key);
            }
        }

        false
    }
    //checks if users exist, and if the key is valid for the user
    //if the user exists Some(user) will be returned
    //if the key is also valid, true will be returned
    //possible return values:
    //(&QuarterbackUser, true) - user exists, and key is valid
    //(&QuarterbackUser, false) - user exists, but key is invalid
    //(None, false) - user does not exist, and therefore key is invalid
    pub fn get_user_authorized_from_str(
        &self,
        userid: &str,
        key: &str,
    ) -> (Option<&QuarterbackUser>, bool) {
        if let Some(user) = self.get_user_from_str(userid) {
            (Some(user), user.check_key(key))
        } else {
            (None, false)
        }
    }

    pub fn get_user_from_str(&self, userid: &str) -> Option<&QuarterbackUser> {
        let userid = Uuid::try_parse(userid);

        if let Ok(userid) = userid {
            self.users.get(&userid)
        } else {
            None
        }
    }

    pub fn get_user(&self, userid: &Uuid) -> Option<&QuarterbackUser> {
        self.users.get(userid)
    }

    //This does the same thing as get_user_authorized_from_str
    pub fn get_user_authorized(
        &self,
        userid: &Uuid,
        key: &str,
    ) -> (Option<&QuarterbackUser>, bool) {
        if let Some(user) = self.get_user(userid) {
            (Some(user), user.check_key(key))
        } else {
            (None, false)
        }
    }

    fn check_user_action(&self, userid: &str, actionid: &str) {
        let userid = parseuuid!(userid, "user id");
        let actionid = parseuuid!(actionid, "action id");

        let user = getuser!(self, &userid);
        let _ = getaction!(self, &actionid);

        let map = self.compute_action_map();

        let result = self.check_user_action_from_uuid(&map, &userid, &actionid);

        if user.super_user {
            println!("User is a super user!");
        }

        if result {
            println!("User {} can execute action {}", userid, actionid);
        } else {
            println!("User {} can NOT execute action {}", userid, actionid);
        }
    }

    pub fn check_user_action_from_str(
        &self,
        map: &QuarterbackActionUsers,
        userid: &str,
        actionid: &str,
    ) -> bool {
        let userid = Uuid::try_parse(userid);
        let actionid = Uuid::try_parse(actionid);

        if let (Ok(userid), Ok(actionid)) = (userid, actionid) {
            return self.check_user_action_from_uuid(map, &userid, &actionid);
        }

        false
    }

    pub fn check_action_exists(&self, action: &str) -> bool {
        let action = Uuid::try_parse(action);

        if let Ok(action) = action {
            self.actions.contains_key(&action)
        } else {
            false
        }
    }

    pub fn get_action_from_str(&self, action: &str) -> Option<&QuarterbackAction> {
        let actionid = Uuid::try_parse(action);

        if let Ok(actionid) = actionid {
            self.actions.get(&actionid)
        } else {
            None
        }
    }

    pub fn check_user_action_from_uuid(
        &self,
        map: &QuarterbackActionUsers,
        userid: &Uuid,
        actionid: &Uuid,
    ) -> bool {
        if !map.map.contains_key(actionid) {
            //action does not exist
            //can not execute an action that doesn't exist!
            //println!("Action does not exist");
            return false;
        }
        let user = self.users.get(userid);
        if let Some(user) = user {
            if user.super_user {
                //user is a super user
                //they can execute anything
                //println!("User is a super user");
                return true;
            }
        } else {
            //user does not exist
            //println!("User does not exist");
            return false;
        }
        if let Some(action) = map.map.get(actionid) {
            //if the set of users contained under this action
            //contains the user, they are allowed to execute
            //the action.
            //println!("action contains");
            return action.contains(userid);
        }
        //return false by default
        false
    }
    fn set_super_user(&mut self, userid: &str, flag: bool) {
        let uuid = parseuuid!(userid, "user id");

        let user = getusermut!(self, &uuid);

        user.super_user = flag;

        println!(
            "User: {} [{}] Super User: {:?}",
            user.user_name, userid, user.super_user
        );
    }

    fn set_user_name(&mut self, userid: &str, name: &str) {
        let uuid = parseuuid!(userid, "user id");

        let user = getusermut!(self, &uuid);

        let orig_name = user.user_name.clone();

        user.user_name = name.to_string();

        println!("Username updated: {} -> {}", orig_name, user.user_name);
    }

    fn add_action(
        &mut self,
        name: &str,
        timeout: u64,
        cooldown: u64,
        action_path: &str,
        action_args: &str,
    ) {
        let uuid = Uuid::new_v4();
        self.actions.insert(
            uuid,
            QuarterbackAction {
                name: name.to_string(),
                action_path: action_path.to_string(),
                action_args: action_args.to_string(),
                timeout: Duration::from_secs(timeout),
                cooldown: Duration::from_secs(cooldown),
                signal: 15,
                log_stdout: false,
            },
        );

        println!("Action {uuid} added");
    }

    fn print_action_by_uuid_str(&self, actionid: &str) {
        let uuid = parseuuid!(actionid, "action id");

        let action = getaction!(self, &uuid);
        println!(
            "{:<40} {:<20} {:<10} {:<10}",
            "ID", "Name", "Timeout", "Cooldown"
        );
        self.print_action(&uuid, action);
    }

    //this doesn't really need &self, but it makes calling it easier
    fn print_action(&self, uuid: &Uuid, action: &QuarterbackAction) {
        println!(
            "{:<40} {:<20} {:<10} {:<10}",
            uuid.to_string(),
            action.name,
            action.timeout.as_secs(),
            action.cooldown.as_secs()
        );
        println!("  -  action_path: {}", action.action_path);
        println!("  -  action_args: {}", action.action_args);
        println!("  - abort_signal: {}", action.signal);
        println!("  -   stdout_log: {}", action.log_stdout);
    }

    fn print_actions(&self) {
        println!(
            "{:<40} {:<20} {:<10} {:<10}",
            "ID", "Name", "Timeout", "Cooldown"
        );
        for (uuid, action) in &self.actions {
            self.print_action(uuid, action);
        }
    }

    fn set_action_name(&mut self, action: &str, name: &str) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_name = action.name.clone();

        action.name = name.to_string();

        println!("Action renamed {} -> {}", orig_name, action.name);
    }

    fn set_action_timeout(&mut self, action: &str, timeout: u64) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_timeout = action.timeout;

        action.timeout = Duration::from_secs(timeout);

        println!(
            "Timeout updated {} -> {}",
            orig_timeout.as_secs(),
            action.timeout.as_secs()
        );
    }

    fn set_action_cooldown(&mut self, action: &str, cooldown: u64) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_cooldown = action.cooldown.as_secs();

        action.cooldown = Duration::from_secs(cooldown);

        println!(
            "Cooldown updated {} -> {}",
            orig_cooldown,
            action.cooldown.as_secs()
        );
    }

    fn set_action_path(&mut self, action: &str, path: &str) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_path = action.action_path.clone();

        action.action_path = path.to_string();

        println!("Path updated {} -> {}", orig_path, action.action_path)
    }

    fn set_action_args(&mut self, action: &str, args: &str) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_args = action.action_args.clone();

        action.action_args = args.to_string();

        println!("Args updated:");
        println!("Original: {orig_args}");
        println!("     New: {}", action.action_args);
    }

    fn set_action_cmd(&mut self, action: &str, path: &str, args: &str) {
        self.set_action_path(action, path);
        println!();
        self.set_action_args(action, args);
    }

    fn set_action_abort_signal(&mut self, action: &str, signal: u8) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_signal = action.signal;

        action.signal = signal;

        println!("Signal updated {} -> {}", orig_signal, action.signal);
    }

    fn set_action_stdout(&mut self, action: &str, log: bool) {
        let uuid = parseuuid!(action, "action id");

        let action = getactionmut!(self, &uuid);

        let orig_stdout = action.log_stdout;

        action.log_stdout = log;

        println!(
            "stdout logging updated {:?} -> {:?}",
            orig_stdout, action.log_stdout
        );
    }

    fn do_action(&mut self, action: &str) {
        let uuid = parseuuid!(action, "action id");

        let action = getaction!(self, &uuid);

        println!("{:=^80}", "Action Executing");
        if let Some(ret) = action.execute_sync() {
            println!("{ret}");
        }
        println!("{:=^80}", "Action Completed");
    }

    fn add_role(&mut self, name: &str) {
        let uuid = Uuid::new_v4();
        self.roles.insert(
            uuid,
            QuarterbackRole {
                role_name: name.to_string(),
                allowed_actions: HashSet::new(),
                allowed_users: HashSet::new(),
            },
        );

        println!("Role {} added", uuid);
    }

    fn clone_role(&mut self, roleid: &str) {
        let uuid = parseuuid!(roleid, "role id");

        let role = getrole!(self, &uuid);

        let new_role = QuarterbackRole {
            role_name: role.role_name.clone(),
            allowed_actions: role.allowed_actions.clone(),
            allowed_users: role.allowed_users.clone(),
        };

        self.roles.insert(Uuid::new_v4(), new_role);
    }

    fn print_role_by_uuid_string(&self, roleid: &str) {
        let uuid = parseuuid!(roleid, "role id");

        let role = getrole!(self, &uuid);

        self.print_role(&uuid, role);
    }

    fn print_role(&self, uuid: &Uuid, role: &QuarterbackRole) {
        println!("  Role ID: {}", uuid);
        println!("Role Name: {}", role.role_name);
        println!();

        let user_map = self.compute_username_map();

        let action_map = self.compute_actionname_map();

        println!("Allowed Actions:");
        println!("{:^36} (Name)", "ID");
        let unknown_name = "!!Unknown Name!!";
        for action in &role.allowed_actions {
            //y'know rust, it's dumb that .get returns an Option<&&str> here
            let name = match action_map.get(action) {
                None => unknown_name,
                Some(name) => *name,
            };
            println!("{:<40} ({})", action, name);
        }
        println!();
        println!("Allowed Users:");

        for user in &role.allowed_users {
            //same here, so dumb that .get returns Option<&&str> *eyeroll*
            let name = match user_map.get(user) {
                None => unknown_name,
                Some(name) => *name,
            };
            println!("{:<40} ({})", user, name);
        }
    }

    fn print_roles(&self) {
        println!("{:=<60}", "");
        for (id, role) in &self.roles {
            self.print_role(id, role);
            println!("{:=<60}", "");
        }
    }

    fn add_role_action(&mut self, roleid: &str, actionid: &str) {
        let roleid = parseuuid!(roleid, "role id");
        let actionid = parseuuid!(actionid, "action id");

        //we don't care about the action itself, just need to verify it exists
        let _ = getaction!(self, &actionid);

        let role = getrolemut!(self, &roleid);

        role.allowed_actions.insert(actionid);

        println!("Action {} added to role {}", actionid, roleid);
    }

    fn add_role_user(&mut self, roleid: &str, userid: &str) {
        let roleid = parseuuid!(roleid, "role id");
        let userid = parseuuid!(userid, "user id");

        let _ = getuser!(self, &userid);

        let role = getrolemut!(self, &roleid);

        role.allowed_users.insert(userid);

        println!("User {} added to role {}", userid, roleid);
    }

    fn del_role_action(&mut self, roleid: &str, actionid: &str) {
        let roleid = parseuuid!(roleid, "role id");
        let actionid = parseuuid!(actionid, "action id");

        let _ = getaction!(self, &actionid);

        let role = getrolemut!(self, &roleid);

        role.allowed_actions.remove(&actionid);

        println!("Action {} removed from role {}", actionid, roleid);
    }

    fn del_role_user(&mut self, roleid: &str, userid: &str) {
        let roleid = parseuuid!(roleid, "role id");
        let userid = parseuuid!(userid, "user id");

        let _ = getuser!(self, &userid);

        let role = getrolemut!(self, &roleid);

        role.allowed_users.remove(&userid);

        println!("User {} removed from role {}", userid, roleid);
    }

    fn del_action(&mut self, actionid: &str) {
        let actionid = parseuuid!(actionid, "action id");

        //same thing here, we don't need the 'aciton', but we do want to check if it exists
        let _ = getaction!(self, &actionid);

        for role in &mut self.roles.values_mut() {
            role.allowed_actions.remove(&actionid);
        }
        self.actions.remove(&actionid);
        println!("Action {} removed", actionid);
    }

    fn del_user(&mut self, userid: &str) {
        let userid = parseuuid!(userid, "user id");

        let _ = getuser!(self, &userid);

        for role in &mut self.roles.values_mut() {
            role.allowed_users.remove(&userid);
        }
        self.users.remove(&userid);
        println!("User {} removed", userid);
    }

    fn del_role(&mut self, roleid: &str) {
        let roleid = parseuuid!(roleid, "role id");

        //again, looks weird since we're deleting it on the next line,
        //but we want to check that it exists before attempting delete
        //(which is what this macro does for us)
        //TODO: As part of the refactor to deuglify, do these too.
        let _ = getrole!(self, &roleid);

        self.roles.remove(&roleid);

        println!("Role {} removed", roleid);
    }

    //used for runtime caching
    //faster lookups by determining which users can execute
    //every action by iterating through all roles
    //deduplicates against multiple roles containing same action
    //i.e. if an action is granted to a user by multipe roles
    //the result of this fn will only contain 1 entry for the user
    //under the action
    pub fn compute_action_map(&self) -> QuarterbackActionUsers {
        let mut map = HashMap::new();

        //(action, user)
        let mut accumulator = Vec::<(&Uuid, &Uuid)>::new();

        for role in self.roles.values() {
            for action in &role.allowed_actions {
                for user in &role.allowed_users {
                    accumulator.push((action, user));
                }
            }
        }

        for id in self.actions.keys() {
            map.insert(*id, HashSet::new());
        }

        for (action, user) in accumulator {
            let actionset = map.get_mut(action);
            match actionset {
                //We should never have a "none", but I'm still not using unwrap.
                None => continue,
                Some(set) => {
                    set.insert(*user);
                }
            }
        }

        QuarterbackActionUsers { map }
    }

    pub fn compute_username_map(&self) -> HashMap<&Uuid, &String> {
        let mut map = HashMap::new();

        for (userid, user) in &self.users {
            map.insert(userid, &user.user_name);
        }

        map
    }

    pub fn compute_actionname_map(&self) -> HashMap<&Uuid, &String> {
        let mut map = HashMap::new();

        for (actionid, action) in &self.actions {
            map.insert(actionid, &action.name);
        }

        map
    }
    fn print_action_map(&self) {
        println!("{:?}", self.compute_action_map());
    }

    fn print_username_map(&self) {
        println!("{:?}", self.compute_username_map());
    }

    fn print_actionname_map(&self) {
        println!("{:?}", self.compute_actionname_map());
    }

    fn hash(password: &str) -> Result<PasswordString, QuarterbackError> {
        QuarterbackConfig::hash_with_print(password, false)
    }

    fn hash_with_print(password: &str, print: bool) -> Result<PasswordString, QuarterbackError> {
        let mut password: String = password.to_string();
        if password.is_empty() {
            password = Uuid::new_v4().to_string();
            print_if!(
                print,
                "No password provided, generating a new UUID as password: {password}",
            );
        } else {
            //println!("Input: {password}");
        }
        let password = password.as_bytes();
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2.hash_password(password, &salt);

        match password_hash {
            Ok(x) => {
                let password_string = x.to_string();
                print_if!(print, "Hash: {password_string}");

                let password_check = Argon2::default().verify_password(password, &x);

                print_if!(print, "Check: {password_check:?}");
                Ok(PasswordString(password_string))
            }
            Err(e) => {
                print_if!(print, "Password hashing failed: {e}");
                Err(QuarterbackError::HashError(e))
            }
        }
    }

    fn is_true(input: Option<&str>) -> bool {
        match input {
            Some("1") | Some("true") => true,
            Some(_) | None => false,
        }
    }

    fn help() {
        printdoc! {"
            QuarterbackConfigurator Help

            This is the interactive configurator for Quarterback. The goal of this configurator
            is to simplify the process of setting up or making changes to the qbconfig.yml file

            Commands are processed interactively. Changes are not saved until the `save` command
            is used to save the current configuration in memory. 

            By default, the configuration is only saved in memory. A configuration backing must
            be set, with the appropriate configuration for that backing, for the configuration
            to persist. Currently 'yaml' is the only backing for configuration. Future versions
            may include additional configuration backings.

            The first thing that should be done on a new configuration is the `backing` command.
            This command provides some additional help text to assist with configuration.

            All configuration for Quarterback can be completed interactively, here's a brief
            overview of all of the commands available in the configurator environment:

            [Command]               [Description]
            help                    display this help text
            version                 display the version of Quarterback
            
            backing                 set the configuration backing persistence

            ==== USER MANAGEMENT ====

            user                    display a specific user
                                        Example: user [userid]

            users                   display the list of currently configured 'users'
                                        user names are not unique, and can be reused
                                        when referring to users in other commands
                                        reference the user by their id, not name

            adduser                 add a user with the following syntax:
                                        adduser [username] [super user flag (default: false)]
                                        Example: adduser david 1
                                            Creates a user `david` that is a super user.
                                        Example: adduser ltorv true
                                            Creates a user `ltorv` that is a super user.
                                        Example: adduser swoz
                                            Creates a user `swoz` that is not a super user.

                                        See `users` command, user names are not unique.

                                        !!!SUPER USERS CAN RUN ANY ACTION!!!
                                          !!!NO ROLE CHECKING PERFORMED!!!
                                        A 'key' is generated that is used to authenticate the user

            resetuserkey            reset the userkey for a specific userid
                or resetuser            if a key is provided, it will be set to the provided key
                or userkey              Example: resetuser [userid] [userkey (default: new uuid)]

            checkuserkey            check if a key is valid for a user
                or userkeycheck         Example: checkuserkey [userid] [userkey]

            checkuseraction          check if a user can execute an action             
                or useractioncheck      This checks against currently configured rolesioncheck  
                                        !!!SUPER USERS CAN RUN ANY ACTION!!!                    
                                        Example: checkuseraction [userid] [actionid]            
                                    
                                    
            checkexecute            check if a user can execute an action, with key verification
                or executecheck         This checks against currently configured roles
                                        !!!SUPER USERS CAN RUN ANY ACTION!!!
                                        This also requires a valid user key, to check without
                                        verifying a valid user key, use `checkuseraction`
                                        Example: checkexecute [userid] [userkey] [actionid]

            superuser               set or unset the super user flag for a specific user
                or usersuper            Example: superuser [userid] [super user flag (default: false)]

            username                set a new name for a userid
                                        Example: username [userid] [name]
                                        See `users` command, user names are not unique.

            ==== ACTION MANAGEMENT ====

            action                  display a specific action
                                        Example: action [actionid]

            actions                 display the list of configured actions
                                        action names are not unique
                                        when referring to actions in other commands use the action id

            actionname              set a new name for an actionid
                                        Example: actionanme [actionid] [name]

            actiontimeout           set a new timeout for an actionid
                                        Example: actiontimeout [actionid] [timeout]

            actioncooldown          set a new cooldown for an actionid
                                        Example: actioncooldown [actionid] [cooldown]

            actionpath              set a new path for an actionid
                                        Example: actionpath [actionid] [path]

            actionargs              set new args for an actionid
                                        Example: actionargs [actionid] [args]

            actioncmd               set a new path and args for an actionid (i.e. redefine command)
                                        Example: actioncmd [actionid] [path] [args...]

            actionabortsignal       set the abort signal to be sent to the process when abort is 
                or actionsignal         called on this action by default, signal 15 (SIGTERM) is 
                                        sent. signal 9 (SIGKILL) will end the action immediately.
                                        set this to 0 to disable the ability to 'abort' an action.
                                        This can be any signal you'd like. It is sent via:
                                            `kill --signal [signal]`
                                        Example: actionabortsignal [actionid] [signal]

            actionstdout            set stdout logging for an action. this is stored in memory.
                or actionlog            set this to false to disable logging stdout to memory.
                                        this does not persist across daemon reloads, and only 
                                        contains the stdout of the last/current run of the action.
                                        Example: actionstdout [actionid] [memory logging flag (default: false)]

            addaction               add a new action
                                        cooldown: how long before this action can be triggered again, in seconds.
                                            0 means it can be triggered again immediately. You probably do not want this.
                                        timeout: how long to wait for this action to execute, in seconds.
                                            0 means that this action will never 'timeout' (i.e. it can run forever).
                                            You probably do not want this. 
                                        Example: addaction [name] [timeout (seconds)] [cooldown (seconds)] [command] [args...]

            actionexec              execute an action
                                        if log_stdout is true for the action, the output is returned interactively
                                        if log_stdout is false for the action, it will display 'action complete' with no other output.

            ==== ROLE MANAGEMENT ====

            addrole                 add a new role
                                        Example: addrole [rolename]
                                        Note: by default, roles are assigned no users or actions

            clonerole               clone a role, and all users and actions assigned to it
                or roleclone            Example: clonerole [roleid]

            role                    display a specific role
                                        Example: role [roleid]

            roles                   display the list of configured roles
                                        role names are not unique
                                        when referring to roles in other commands use the role id


            addroleaction           add an action to a role
                                        Example: addroleaction [roleid] [actionid]

            addroleuser             add a user to a role
                                        Example: addroleuser [roleid] [userid]


            ==== OBJECT MANAGEMENT ====
                                        

            delaction               delete an action
                                        Example: delaction [actionid]

            delroleaction           delete an action from a role
                                        Example: delroleaction [roleid] [actionid]

            delroleuser             delete a user from a role
                                        Example: delroleuser [roleid] [userid]

            deluser                 delete a user
                                        Example: deluser [userid]

            delrole                 delete a role
                                        Example: delrole [roleid]

            save                    save the configuration
                                        use `backing` to see where the configuration will be saved!

            exit                    exit the configurator, remember to save first!
                or quit
            
            exit!
                or quit!            exit the configurtor, without save checking, just like vim.


            ==== DEVELOPMENT ====

            The following commands are included for testing only. They may be removed at any time:

            [Command]               [Description]
            is_true                 outputs whether the following 'word' evaluates to 'true'
                                        used in other commands to determine flag is true/false

            hash                    hash the next 'word' with argon2id and output the result
                                        used in commands that generate 'keys' to prevent plain
                                        text secrets in the backing stores
                                        Note: a new salt is generated for every hash
                                        You *will* receive different output on every run,
                                        even from the same input.
                                        If `Check: Ok(())` is displayed, the hash and the
                                        verification succeeded.

            show_action_map         compute the map of actions and their allowed users
                                        printing the map to stdout
                                        (i.e. actionid => set(userids))

            show_action_name_map    compute the action_name map
                                        printing the map to stdout
                                        (i.e. actionid => name)

            show_user_name_map      compute the user_name map
                                        printing the map to stdout
                                        (i.e. userid => name)

            "}
    }

    fn eval(&mut self, input: &str) -> Result<EvalResult<()>, ()> {
        let mut input_vec = input.trim_end().split(' ');

        let cmd = input_vec.next();

        //TODO: Make this not so ugly, i.e. break out all of the arms into their own fn
        match cmd {
            Some("version") | Some("v") => println!("Version: {}", env!("CARGO_PKG_VERSION")),
            Some("users") | Some("u") => self.print_users(),
            Some("user") => {
                let user = input_vec.next();

                if let Some(user) = user {
                    self.print_user(user);
                } else {
                    println!("ERROR: A user id must be provided!");
                    println!("    Example: user [userid]");
                }
            }
            Some("adduser") => {
                let name = input_vec.next();
                let super_user = QuarterbackConfig::is_true(input_vec.next());
                if let Some(name) = name {
                    self.add_user(name, super_user);
                } else {
                    println!("ERROR: A user name must be provided.");
                    println!("    Example: adduser [name] [super user: (default false)]");
                }
            }
            Some("resetuserkey") | Some("resetuser") | Some("userkey") => {
                let user = input_vec.next();
                let key = input_vec.next();

                if let (Some(user), Some(key)) = (user, key) {
                    self.reset_user_key(user, key);
                } else if let (Some(user), None) = (user, key) {
                    let key = Uuid::new_v4().to_string();
                    println!("Generating new key: {key} --- SAVE THIS KEY - IT WILL NEVER BE DISPLAYED AGAIN!");
                    self.reset_user_key(user, &key);
                } else {
                    println!("ERROR: A userid and key must be provided!");
                    println!("    Example: resetuserkey [userid] [key: default(new Uuid)]");
                }
            }
            Some("checkuserkey") | Some("userkeycheck") => {
                let user = input_vec.next();
                let key = input_vec.next();

                if let (Some(user), Some(key)) = (user, key) {
                    self.check_user_key(user, key);
                } else {
                    println!("ERROR: A userid and key must be provided!");
                    println!("    Example: checkuserkey [userid] [key]");
                }
            }
            Some("checkuseraction") | Some("useractioncheck") => {
                let user = input_vec.next();
                let action = input_vec.next();

                if let (Some(user), Some(action)) = (user, action) {
                    self.check_user_action(user, action);
                } else {
                    println!("ERROR: A userid and actionid must be provided!");
                    println!("    Example: checkuseraction [userid] [actionid]");
                }
            }
            Some("checkexecute") | Some("executecheck") => {
                let user = input_vec.next();
                let key = input_vec.next();
                let action = input_vec.next();

                //TODO: Deuglify, I hate this.
                if let (Some(user), Some(key), Some(action)) = (user, key, action) {
                    if self.check_user_key_from_str(user, key) {
                        let map = self.compute_action_map();
                        if self.check_user_action_from_str(&map, user, action) {
                            println!(
                                "SUCCESS: User {} authenticated, and can execute action {}",
                                user, action
                            );
                        } else {
                            let uuid = Uuid::try_parse(action);

                            let action_exists =
                                self.actions.contains_key(&uuid.unwrap_or(Uuid::new_v4()));

                            if !action_exists {
                                println!("ERROR: Action {} does not exist", action);
                            } else {
                                println!("ERROR: User {} can NOT execute action {}", user, action);
                            }
                        }
                    } else {
                        println!("ERROR: User Key Invalid!");
                    }
                } else {
                    println!("ERROR: A userid, userkey, and actionid must be provided!");
                    println!("    Example: checkexecute [userid] [userkey] [actionid]");
                }
            }
            Some("actionexec") => {
                let action = input_vec.next();

                if let Some(action) = action {
                    self.do_action(action);
                } else {
                    println!("ERROR: An action ID must be provided!");
                    println!("    Example: actionexec [actionid]");
                }
            }
            Some("superuser") | Some("usersuper") => {
                let user = input_vec.next();
                let flag = QuarterbackConfig::is_true(input_vec.next());

                if let Some(user) = user {
                    self.set_super_user(user, flag);
                } else {
                    println!("ERROR: A userid must be provided!");
                    println!("    Example: superuser [userid] [flag: default(false)]");
                }
            }
            Some("username") => {
                let user = input_vec.next();
                let name = input_vec.next();

                if let (Some(user), Some(name)) = (user, name) {
                    self.set_user_name(user, name);
                } else {
                    println!("ERROR: A userid and name must be provided!");
                    println!("    Example: username [userid] [name]");
                }
            }
            Some("action") => {
                let action = input_vec.next();

                if let Some(action) = action {
                    self.print_action_by_uuid_str(action);
                } else {
                    println!("ERROR: An action id must be provided!");
                    println!("    Example: action [actionid]");
                }
            }
            Some("actions") | Some("a") => self.print_actions(),
            Some("addaction") => {
                let name = input_vec.next();
                let timeout = input_vec.next();
                let cooldown = input_vec.next();
                let action_path = input_vec.next();
                let action_args: String = input_vec.map(|arg| arg.to_string() + " ").collect();
                //why does adding .trim_end() to the above line require type annotations, but this
                //doesn't?
                //TODO: Figure this out
                let action_args = action_args.trim_end();

                //println!("name: {name:?}");
                //println!("timeout: {timeout:?}");
                //println!("cooldown: {cooldown:?}");
                //println!("action_path: {action_path:?}");
                //println!("action_args: {action_args:?}");

                if let (Some(name), Some(timeout), Some(cooldown), Some(path)) =
                    (name, timeout, cooldown, action_path)
                {
                    let timeout = u64::from_str(timeout);
                    let cooldown = u64::from_str(cooldown);
                    if let (Ok(timeout), Ok(cooldown)) = (timeout, cooldown) {
                        if timeout > cooldown {
                            println!("WARNING: Timeout should not exceed cooldown.");
                            println!("    You will not be able to do anything with tasks started prior to latest run!");
                            println!("    i.e. If the task is 'run' again before expires, but after cooldown, the previous run can not be 'aborted'");
                            println!("    The stdout and stderr logs will also end up concatenated together if stdout logging is enabled.");
                        }
                        self.add_action(name, timeout, cooldown, path, action_args);
                    } else {
                        println!("ERROR: Timeout and cooldown must be positive integers!");
                    }
                } else {
                    println!("ERROR: Requires a name, timeout, cooldown, path, and optional args!");
                    println!("    Example: addaction [name] [timeout (seconds)] [cooldown (seconds)] [path] [args (optional)...]");
                }
            }
            Some("actionname") => {
                let action = input_vec.next();
                let name = input_vec.next();

                if let (Some(action), Some(name)) = (action, name) {
                    self.set_action_name(action, name);
                } else {
                    println!("ERROR: Requires an action id and a name!");
                    println!("    Example: actionname [actionid] [name]");
                }
            }
            Some("actiontimeout") => {
                let action = input_vec.next();
                let timeout = input_vec.next();

                if let (Some(action), Some(timeout)) = (action, timeout) {
                    let timeout = u64::from_str(timeout);
                    if let Ok(timeout) = timeout {
                        self.set_action_timeout(action, timeout);
                    } else {
                        println!("ERROR: Timeout must be a positive integer");
                    }
                } else {
                    println!("ERROR: Requires an action id and a timeout");
                    println!("    Example: actiontimeout [actionid] [timeout]");
                }
            }
            Some("actioncooldown") => {
                let action = input_vec.next();
                let cooldown = input_vec.next();

                if let (Some(action), Some(cooldown)) = (action, cooldown) {
                    let cooldown = u64::from_str(cooldown);
                    if let Ok(cooldown) = cooldown {
                        self.set_action_cooldown(action, cooldown);
                    } else {
                        println!("ERROR: Cooldown must be a positive integer");
                    }
                } else {
                    println!("ERROR: Requires an action id and a cooldown");
                    println!("    Example: actioncooldown [actionid] [cooldown]");
                }
            }
            Some("actionpath") => {
                let action = input_vec.next();
                let path = input_vec.next();

                if let (Some(action), Some(path)) = (action, path) {
                    self.set_action_path(action, path);
                } else {
                    println!("ERROR: An action id and path must be provided!");
                    println!("    Example: actionpath [actionid] [path]");
                }
            }
            Some("actionargs") => {
                let action = input_vec.next();
                let action_args: String = input_vec.map(|arg| arg.to_string() + " ").collect();
                //TODO: Figure this out, same reason as addaction
                let action_args = action_args.trim_end();

                if let Some(action) = action {
                    self.set_action_args(action, action_args);
                } else {
                    println!("ERROR: An action id must be provided!");
                    println!("    Example: actionargs [actionid] [args: (optional)...]");
                }
            }
            Some("actioncmd") => {
                let action = input_vec.next();
                let action_path = input_vec.next();
                let action_args: String = input_vec.map(|arg| arg.to_string() + " ").collect();
                //TODO: Figure this out, same reason as addaction
                let action_args = action_args.trim_end();

                if let (Some(action), Some(action_path)) = (action, action_path) {
                    self.set_action_cmd(action, action_path, action_args);
                } else {
                    println!("ERROR: An action id and path must be provided!");
                    println!("    Example: actioncmd [actionid] [path] [args (optional)...]");
                }
            }
            Some("actionabortsignal") | Some("actionsignal") => {
                let action = input_vec.next();
                let action_signal = input_vec.next();

                if let (Some(action), Some(action_signal)) = (action, action_signal) {
                    if let Ok(action_signal) = u8::from_str(action_signal) {
                        self.set_action_abort_signal(action, action_signal);
                    } else {
                        println!("ERROR: Signal must be an integer between 0-255");
                        println!("    0 disables abort functionality");
                    }
                } else {
                    println!("ERROR: An action id and signal must be provided!");
                    println!("    Example: actionsignal [actionid] [signal]");
                }
            }
            Some("actionstdout") | Some("actionlog") => {
                let action = input_vec.next();
                let action_log = input_vec.next();

                if let Some(action) = action {
                    let action_log = QuarterbackConfig::is_true(action_log);
                    self.set_action_stdout(action, action_log);
                } else {
                    println!("ERROR: An action id and flag must be provided!");
                    println!("    If true, log the action output into memory");
                    println!("    false by default");
                    println!("    Example: actionlog [actionid] [logging flag: default(false)]");
                }
            }
            Some("addrole") => {
                let name = input_vec.next();

                if let Some(name) = name {
                    self.add_role(name);
                } else {
                    println!("ERROR: A name must be provided!");
                    println!("    Example: addrole [name]");
                }
            }
            Some("clonerole") | Some("roleclone") => {
                let role = input_vec.next();

                if let Some(role) = role {
                    self.clone_role(role);
                } else {
                    println!("ERROR: A role ID must be provided!");
                    println!("    Example: clonerole [roleid]");
                }
            }
            Some("role") => {
                let role = input_vec.next();

                if let Some(role) = role {
                    self.print_role_by_uuid_string(role);
                } else {
                    println!("ERROR: A role ID must be provided!");
                    println!("    Example: role [roleid]");
                }
            }
            Some("roles") => {
                self.print_roles();
            }
            Some("addroleaction") => {
                let role = input_vec.next();
                let action = input_vec.next();

                if let (Some(role), Some(action)) = (role, action) {
                    self.add_role_action(role, action);
                } else {
                    println!("ERROR: A role ID and action ID must be provided!");
                    println!("    Example: addroleaction [roleid] [actionid]");
                }
            }
            Some("addroleuser") => {
                let role = input_vec.next();
                let user = input_vec.next();

                if let (Some(role), Some(user)) = (role, user) {
                    self.add_role_user(role, user);
                } else {
                    println!("ERROR: A role ID and user ID must be provided!");
                    println!("    Example: addroleuser [roleid] [userid]");
                }
            }
            Some("delaction") => {
                let action = input_vec.next();

                if let Some(action) = action {
                    self.del_action(action);
                } else {
                    println!("ERROR: An action ID must be provided!");
                    println!("    Example: delaction [actionid]");
                }
            }
            Some("delroleaction") => {
                let role = input_vec.next();
                let action = input_vec.next();

                if let (Some(role), Some(action)) = (role, action) {
                    self.del_role_action(role, action);
                } else {
                    println!("ERROR: A role ID and action ID must be provided!");
                    println!("    Example: delroleaction [roleid] [actionid]");
                }
            }
            Some("delroleuser") => {
                let role = input_vec.next();
                let user = input_vec.next();

                if let (Some(role), Some(user)) = (role, user) {
                    self.del_role_user(role, user);
                } else {
                    println!("ERROR: A role ID and user ID must be provided!");
                    println!("    Example: delroleuser [roleid] [userid]");
                }
            }
            Some("deluser") => {
                let user = input_vec.next();

                if let Some(user) = user {
                    self.del_user(user);
                } else {
                    println!("ERROR: A user ID must be provided!");
                    println!("    Example: deluser [userid]");
                }
            }
            Some("delrole") => {
                let role = input_vec.next();

                if let Some(role) = role {
                    self.del_role(role);
                } else {
                    println!("ERROR: A role ID must be provided!");
                    println!("    Example: delrole [roleid]");
                }
            }
            Some("save") => self.save(),
            Some("backing") => self.backing(&mut input_vec),
            Some("is_true") => {
                println!("{:?}", QuarterbackConfig::is_true(input_vec.next()));
            }
            Some("hash") => {
                let _ = QuarterbackConfig::hash_with_print(input_vec.next().unwrap_or(""), true);
            }
            Some("show_action_map") => {
                self.print_action_map();
            }
            Some("show_action_name_map") => {
                self.print_actionname_map();
            }
            Some("show_user_name_map") => {
                self.print_username_map();
            }
            Some("help") => QuarterbackConfig::help(),
            Some("exit") | Some("quit") => {
                //TODO: Have you saved? (y/n)
                //      Do you want to? (y/n)
                return Ok(EvalResult::ExitRepl);
            }
            //                              See? Told you, just like vim!
            Some("exit!") | Some("quit!") | Some(":q!") => {
                return Ok(EvalResult::ExitRepl);
            }
            Some("") => {}
            Some(x) => println!("Unknown command: {x}"),
            None => {}
        }

        println!();

        Ok(EvalResult::Continue)
    }
}

struct HttpErr;

impl HttpErr {
    pub fn or_err(status: http::StatusCode) -> poem::Error {
        poem::Error::from_status(status)
    }
    pub fn http_err<T>(status: http::StatusCode) -> poem::Result<T> {
        Err(poem::Error::from_status(status))
    }
    pub fn too_many_reqs<T>() -> poem::Result<T> {
        HttpErr::http_err(http::StatusCode::TOO_MANY_REQUESTS)
    }
    pub fn internal_server_error<T>() -> poem::Result<T> {
        HttpErr::http_err(http::StatusCode::INTERNAL_SERVER_ERROR)
    }
    pub fn unauthorized<T>() -> poem::Result<T> {
        HttpErr::http_err(http::StatusCode::UNAUTHORIZED)
    }
    pub fn or_unauthorized() -> poem::Error {
        HttpErr::or_err(http::StatusCode::UNAUTHORIZED)
    }
}

#[derive(Debug)]
struct RateLimit {
    limit: Duration,
    last_allowed: DateTime<Utc>,
}

struct RateLimiting {
    //RwLock is used
    rate_map: RwLock<HashMap<String, RateLimit>>,
}

//if a panic occurs while writing then we *do* want to panic
//writing to a hashmap should never fail, except with oom
//per RwLock<T> docs, read().unwrap() should never panic, unless
//a write() panics
#[allow(clippy::unwrap_used)]
impl RateLimiting {
    //`limit_secs` is dynamically configurable
    //this will check based upon the last successful run
    //and, if the action can run, set the rate limit to `limit_secs`
    //if the action does not currently exist, this will add the action
    //to the RateLimiting.rate_map, with the passed `limit_secs`
    //rate_map is "lazy" it doesn't need to know about actions until
    //they are checked for a ratelimit.
    //returns poem::Result<T> so that this can be used with ? operator
    //i.e. rate_map.run_check(action, 30).await?
    pub fn run_check_chain<T>(&self, action: &str, limit_secs: u64, chain: T) -> poem::Result<T> {
        let limit = self.rate_map.read().unwrap();
        //TODO: Refactor this, it looks too much like C and I don't like it
        //there's got to be a more "rusty" way of doing this
        if let Some(action_limit) = limit.get(action) {
            let now = Utc::now();
            if (action_limit.last_allowed + action_limit.limit) < now {
                //need to drop read ref to limit so that write will work in insert_action
                drop(limit);
                self.insert_action(action.to_string(), limit_secs);
                Ok(chain)
            } else {
                //println!("Action: {action} blocked by rate limiter");
                HttpErr::too_many_reqs()
            }
        } else {
            //action does not currently exist, add to rate_map

            //same here, need to drop read ref to limit so that insert_action will work
            drop(limit);
            self.insert_action(action.to_string(), limit_secs);
            Ok(chain)
        }
    }

    pub fn run_check(&self, action: &str, limit_secs: u64) -> poem::Result<()> {
        self.run_check_chain(action, limit_secs, ())
    }

    pub fn check_limit(&self, action: &str) -> i64 {
        let limit = self.rate_map.read().unwrap();

        if let Some(action_limit) = limit.get(action) {
            let limit = action_limit.last_allowed + action_limit.limit;
            let now = Utc::now();
            if limit > now {
                let remaining = limit - now;
                remaining.num_seconds()
            } else {
                0
            }
        } else {
            0
        }
    }

    fn insert_action(&self, action: String, limit_secs: u64) {
        self.rate_map
            .write()
            .unwrap()
            .insert(action.to_string(), self.rate_limit(limit_secs));
    }
    //don't really need &self, but makes calling this easier
    //TODO: Probably change this to new()
    fn rate_limit(&self, limit_secs: u64) -> RateLimit {
        RateLimit {
            limit: Duration::from_secs(limit_secs),
            last_allowed: Utc::now(),
        }
    }
}

struct TaskHandle {
    task: tokio::task::JoinHandle<()>,
    expires: DateTime<Utc>,
}

struct TaskManager {
    tasks: std::sync::Arc<RwLock<HashMap<Uuid, TaskHandle>>>,
    //more generics are more better? right?                >>>>>
    task_history: std::sync::Arc<RwLock<HashMap<Uuid, Vec<DateTime<Utc>>>>>,
    monitor_running: std::sync::atomic::AtomicBool,
}

enum TaskState {
    Running,
    Finished,
    UnknownTask,
}

enum TaskAbortStatus {
    AbortRequested,
    TaskUnknown,
    Finished,
}

//same reason as RateLimiting
#[allow(clippy::unwrap_used)]
impl TaskManager {
    fn new() -> Self {
        let atomic_false = std::sync::atomic::AtomicBool::new(false);
        TaskManager {
            tasks: std::sync::Arc::new(RwLock::new(HashMap::new())),
            task_history: std::sync::Arc::new(RwLock::new(HashMap::new())),
            monitor_running: atomic_false,
        }
        //TODO: Add task watcher / history status logger
        //as a seperate thread
    }

    //maybe I can figure out a better way to do this, but for now... so be it
    fn start_monitor(&self) {
        if self
            .monitor_running
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let tasks = self.tasks.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut abort_monitor: Vec<Uuid> = Vec::new();

            loop {
                interval.tick().await;
                for task in tasks.read().unwrap().iter() {
                    //println!("{:?} {:?}", task.0, task.1.expires);
                    if (Utc::now() > task.1.expires) && !task.1.task.is_finished() {
                        println!(
                            "{:?} - MONITOR: Task {} expired... aborting...",
                            Local::now(),
                            task.0
                        );
                        abort_monitor.push(*task.0);
                        task.1.task.abort();
                    }
                }
                let mut still_aborting: Vec<Uuid> = Vec::new();

                for task in abort_monitor.iter() {
                    //this also "magically" handles tasks handles that are removed
                    //from `tasks`, if we can't get a taskhandle for the Uuid
                    //it is dropped from abort_monitor
                    if let Some(task_handle) = tasks.read().unwrap().get(task) {
                        if task_handle.task.is_finished() {
                            println!("{:?} - MONITOR: Task {} aborted", Local::now(), task);
                        } else {
                            //I don't particularly like this, I'd prefer if I could just move this
                            //Maybe I should try into_iter()?
                            //TODO: ^
                            still_aborting.push(*task);
                        }
                    }
                }

                abort_monitor = still_aborting;
            }
        });
        self.monitor_running
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn get_timeout_secs(&self, task_id: &Uuid) -> i64 {
        if let Some(task) = self.tasks.read().unwrap().get(task_id) {
            let now = Utc::now();
            if task.expires > now {
                (task.expires - now).num_seconds()
            } else {
                0
            }
        } else {
            0
        }
    }

    fn get_run_history(&self, task_id: &Uuid) -> Option<Vec<DateTime<Utc>>> {
        //I mean... is this really any worse than what a web API would technically be doing
        //here? You have to read out the entire struct to return it over the network...
        //This just isn't going through the network... yet, anyway
        self.task_history.read().unwrap().get(task_id).cloned()
    }

    fn get_task_state(&self, task_id: &Uuid) -> TaskState {
        if let Some(task) = self.tasks.read().unwrap().get(task_id) {
            if task.task.is_finished() {
                //I really wish JoinHandles kept track of if they were aborted
                //I should probably make another type that tracks this...
                //TODO:             ^
                TaskState::Finished
            } else {
                TaskState::Running
            }
        } else {
            TaskState::UnknownTask
        }
    }

    fn abort_task(&self, task_id: &Uuid) -> TaskAbortStatus {
        if let Some(handle) = self.tasks.read().unwrap().get(task_id) {
            if handle.task.is_finished() {
                TaskAbortStatus::Finished
            } else {
                handle.task.abort();
                TaskAbortStatus::AbortRequested
            }
        } else {
            TaskAbortStatus::TaskUnknown
        }
    }

    fn add_task(&self, task_id: Uuid, task: tokio::task::JoinHandle<()>, timeout: Duration) {
        //start the monitor if it's not already running
        self.start_monitor();
        let expires = Utc::now() + timeout;
        self.tasks
            .write()
            .unwrap()
            .insert(task_id, TaskHandle { task, expires });
        let task_history = self.task_history.clone();
        let mut task_history = task_history.write().unwrap();

        if let Some(history) = task_history.get_mut(&task_id) {
            history.push(Utc::now());
        } else {
            task_history.insert(task_id, vec![Utc::now()]);
        }
    }
}

struct Api {
    admin_key: String,
    config: QuarterbackConfig,
    allow_print_config: bool,
    request_logging: bool,
    action_user_map: QuarterbackActionUsers,
    task_manager: TaskManager,
    action_status: std::sync::Arc<RwLock<HashMap<Uuid, String>>>,
    rate_limiter: RateLimiting,
    //used as a global limit to the endpoints themselves
    //this is checked seperately from the cooldown of the actual actions
    //used to prevent bruteforce attacks
    global_rate_limit_secs: u64,
}

#[OpenApi]
impl Api {
    //this feels like it should be a macro
    fn get_now(&self) -> String {
        format!("{:?}", chrono::offset::Local::now())
    }
    //this also feels like it should be a macro
    fn req_log(&self, logline: String) {
        if self.request_logging {
            println!("{} - {}", self.get_now(), logline);
        }
    }

    /// Hello World
    #[oai(path = "/", method = "get")]
    async fn index(&self) -> PlainText<&'static str> {
        //I don't believe that / should be logged with Quarterback
        //This is really just to "prove" that it's working
        //No rate limiting is applied, if you see "Hello World"
        //through your reverse proxy you know it's working.
        //if self.request_logging {
        //    println!("{} GET /", self.get_now());
        //}
        PlainText("Hello World")
    }

    //will return http::StatusCode::TOO_MANY_REQUESTS if rate limit is exceeded
    //otherwise it will return Ok(())
    async fn check_rate_limit(&self, action: &str, limit_secs: u64) -> poem::Result<()> {
        self.rate_limiter.run_check(action, limit_secs)
    }

    #[oai(path = "/config/:authkey", method = "get")]
    async fn print_config(&self, authkey: Path<Option<String>>) -> poem::Result<PlainText<String>> {
        self.check_rate_limit("configprint", self.global_rate_limit_secs)
            .await?;
        let authkey = match authkey.0 {
            None => "".to_string(),
            Some(key) => key,
        };
        self.req_log(format!(
            "GET /config/{} ; allow_print_config: {:?}",
            &authkey, self.allow_print_config
        ));
        if !self.allow_print_config {
            //Configuration printing is not allowed.
            return Err(poem::Error::from_status(http::StatusCode::FORBIDDEN));
        }

        if self.admin_key.eq(&authkey) {
            let ret = self.config.to_yaml().or(Err(poem::Error::from_status(
                http::StatusCode::INTERNAL_SERVER_ERROR,
            )))?;
            //Admin key matches and configuration printing is allowed
            Ok(PlainText(ret))
        } else {
            //Admin key does not match, but configuration printing is allowed
            Err(poem::Error::from_status(http::StatusCode::UNAUTHORIZED))
        }
    }

    #[oai(path = "/config/limits/:authkey", method = "get")]
    async fn print_rate_limits(
        &self,
        authkey: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        self.check_rate_limit("ratelimitprint", self.global_rate_limit_secs)
            .await?;
        let authkey = match authkey.0 {
            None => "".to_string(),
            Some(key) => key,
        };

        self.req_log(format!(
            "GET /config/limits/{} ; allow_print_config: {:?}",
            &authkey, self.allow_print_config
        ));

        if self.admin_key.eq(&authkey) {
            let ret = format!("{:?}", self.rate_limiter.rate_map);
            Ok(PlainText(ret))
        } else {
            HttpErr::unauthorized()
        }
    }

    async fn endpoint_ratelimit(&self, endpoint: &str) -> poem::Result<()> {
        let endpoint_limit = format!("endpoint!{endpoint}");
        self.check_rate_limit(&endpoint_limit, self.global_rate_limit_secs)
            .await?;
        Ok(())
    }

    //used to check if an action exists before applying it's "global" rate limit
    //returns a reference to the QuarterbackAction if it exists
    async fn action_ratelimit(&self, actionid: &str) -> poem::Result<&QuarterbackAction> {
        if let Some(action) = self.config.get_action_from_str(actionid) {
            let action_limit = format!("action!{actionid}");
            self.check_rate_limit(&action_limit, action.cooldown.as_secs())
                .await?;
            Ok(action)
        } else {
            HttpErr::unauthorized()
        }
    }

    //maybe this can be a macro?
    fn unwrap_action_user_key(
        action: Option<String>,
        user: Option<String>,
        key: Option<String>,
    ) -> Result<(String, String, String), poem::Error> {
        let action = action.unwrap_or_default();
        let user = user.unwrap_or_default();
        let key = key.unwrap_or_default();

        if action.is_empty() || user.is_empty() || key.is_empty() {
            HttpErr::unauthorized()
        } else {
            Ok((action, user, key))
        }
    }

    //this does check if the user is authorized to run the action
    async fn action_init(
        &self,
        endpoint: &str,
        action: Option<String>,
        user: Option<String>,
        key: Option<String>,
    ) -> Result<(QuarterbackAction, Uuid, &QuarterbackUser, bool), poem::Error> {
        self.endpoint_ratelimit(endpoint).await?;
        let (actionid, userid, key) = Api::unwrap_action_user_key(action, user, key)?;
        //the action cooldown rate limiter only applies on the /run endpoint
        //all other endpoints are "non destructive" and don't need the same protection
        let action = if "run".eq(endpoint) {
            self.action_ratelimit(&actionid).await?
        } else {
            self.config
                .get_action_from_str(&actionid)
                .ok_or(HttpErr::or_unauthorized())?
        };
        let actionid = Uuid::try_parse(&actionid).or(HttpErr::unauthorized())?;
        let userid = Uuid::try_parse(&userid).or(HttpErr::unauthorized())?;
        //now, this is something that I think is incredible about rust...
        //destructuring a tuple, and checking a result type...
        //all with... (Some(user), true) = fn()
        //honestly, it's beautiful
        //much prettier than a multi layered if statement
        //TODO: Make the other multi layered if statements this pretty
        //TODO: Change this bool to something like User::ValidKey as enum
        if let (Some(user), true) = self.config.get_user_authorized(&userid, &key) {
            let action_user =
                self.config
                    .check_user_action_from_uuid(&self.action_user_map, &userid, &actionid);

            if !action_user {
                HttpErr::unauthorized()
            } else {
                Ok((action.clone(), actionid, user, action_user))
            }
        } else {
            HttpErr::unauthorized()
        }
    }

    #[oai(path = "/run/:actionid/:user/:key", method = "get")]
    async fn action_run(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) =
            self.action_init("run", actionid.0, user.0, key.0).await?;
        self.req_log(format!(
            "GET /run/{}/{}/{}",
            action.name, user.user_name, validkey
        ));
        //println!("{:?}; {:?}; {:?}", action, user, validkey);

        let action_status = self.action_status.clone();

        if let Ok(mut writer) = action_status.write() {
            writer.insert(actionid, format!("Running started at: {}", Utc::now()));
        }

        //this makes a copy of actionid
        //Clippy suggested this, but I feel it makes it less clear what's going on
        //idk, maybe I'll ignore clippy on this one...
        let cloneid = actionid;
        //same here, I think removing .clone() makes it less clear
        //that it is a copy...
        //again, I may just ignore clippy on this one...
        let clonetimeout = action.timeout;
        let task = tokio::spawn(async move {
            let res = action.execute().await;
            if let Some(res) = res {
                if let Ok(mut writer) = action_status.write() {
                    writer.insert(actionid, res);
                }
            }
        });
        self.task_manager.add_task(cloneid, task, clonetimeout);
        Ok(PlainText("Task Started".to_string()))

        //let output = action.execute().await;

        //match output {
        //    Some(output) => Ok(PlainText(output)),
        //    None => HttpErr::internal_server_error(),
        //}

        //Err(poem::Error::from_status(http::StatusCode::NOT_IMPLEMENTED))
    }

    #[oai(path = "/status/:actionid/:user/:key", method = "get")]
    async fn action_status(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) = self
            .action_init("status", actionid.0, user.0, key.0)
            .await?;
        self.req_log(format!(
            "GET /status/{}/{}/{}",
            action.name, user.user_name, validkey
        ));
        let action_status = self.action_status.clone();
        //why can't this be the end of this fn?
        let ret = match action_status.read() {
            Err(_) => HttpErr::internal_server_error(),
            Ok(reader) => match reader.get(&actionid) {
                None => Ok(PlainText("Action has not yet run!".to_string())),
                Some(res) => Ok(PlainText(res.clone())),
            },
        };
        //Rust, why do you want this?
        //Stop it, don't try it. You can't remove this.
        //if you take away let ret and try to end fn with just the match above
        //rust doesn't like this, it's convinced it doesn't live long enough
        ret
    }

    //like status, but just what it's state is, without all the "pretty" formatting and logging
    #[oai(path = "/state/:actionid/:user/:key", method = "get")]
    async fn action_state(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) =
            self.action_init("state", actionid.0, user.0, key.0).await?;
        self.req_log(format!(
            "GET /state/{}/{}/{}",
            action.name, user.user_name, validkey
        ));

        let state = self.task_manager.get_task_state(&actionid);

        //if we get UnknownTask back from TaskManager it means TaskManager has
        //never seen the task, not that the task doesn't exist
        //if we reach this point, the task ("action") definitely exists
        match state {
            TaskState::Running => Ok(PlainText("Running".to_string())),
            TaskState::Finished => Ok(PlainText("Done / Stopped".to_string())),
            TaskState::UnknownTask => Ok(PlainText("Task Never Started".to_string())),
        }
    }

    #[oai(path = "/abort/:actionid/:user/:key", method = "get")]
    async fn action_abort(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) =
            self.action_init("abort", actionid.0, user.0, key.0).await?;
        self.req_log(format!(
            "GET /abort/{}/{}/{}",
            action.name, user.user_name, validkey
        ));

        let abort_status = self.task_manager.abort_task(&actionid);

        //just like state, if we get TaskUnknown, it means TaskManager has
        //never seen the task, not that the task doesn't exist
        //if we reach this point, it's already been validated that the task ("action")
        //definitely exists
        match abort_status {
            TaskAbortStatus::AbortRequested => Ok(PlainText("Abort requested...".to_string())),
            TaskAbortStatus::Finished => Ok(PlainText("Aborted / Finished".to_string())),
            TaskAbortStatus::TaskUnknown => Ok(PlainText("Task Never Started".to_string())),
        }
    }

    #[oai(path = "/timeout/:actionid/:user/:key", method = "get")]
    async fn action_timeout(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) = self
            .action_init("timeout", actionid.0, user.0, key.0)
            .await?;
        self.req_log(format!(
            "GET /timeout/{}/{}/{}",
            action.name, user.user_name, validkey
        ));

        let timeout = self.task_manager.get_timeout_secs(&actionid);
        let timeout = format!("{timeout}");

        Ok(PlainText(timeout))
    }

    #[oai(path = "/cooldown/:actionid/:user/:key", method = "get")]
    async fn action_cooldown(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) = self
            .action_init("cooldown", actionid.0, user.0, key.0)
            .await?;
        self.req_log(format!(
            "GET /cooldown/{}/{}/{}",
            action.name, user.user_name, validkey
        ));

        let limit = self.rate_limiter.check_limit(&format!("action!{actionid}"));
        //*eye roll*
        let limit = format!("{limit}");

        Ok(PlainText(limit))
    }

    #[oai(path = "/log/:actionid/:user/:key", method = "get")]
    async fn action_log(
        &self,
        actionid: Path<Option<String>>,
        user: Path<Option<String>>,
        key: Path<Option<String>>,
    ) -> poem::Result<PlainText<String>> {
        let (action, actionid, user, validkey) =
            self.action_init("log", actionid.0, user.0, key.0).await?;
        self.req_log(format!(
            "GET /log/{}/{}/{}",
            action.name, user.user_name, validkey
        ));

        let log = self.task_manager.get_run_history(&actionid);

        match log {
            None => Ok(PlainText("Task Never Started".to_string())),
            Some(log) => {
                let mut ret = String::new();
                for exec in log {
                    ret += &format!("{}\n", exec);
                }

                Ok(PlainText(ret))
            }
        }
    }
}

#[derive(Debug, Copy, Clone, ValueEnum)]
enum QuarterbackMode {
    Config,
    Daemon,
    //TODO: Add eval mode
    //should operate as configurator, but eval from stdin
}

impl QuarterbackMode {
    fn configurator(config: &str) {
        println!("Quarterback Configurator:");
        println!();

        let mut conf: QuarterbackConfig;

        if config.is_empty() {
            conf = QuarterbackConfig::new();
            println!("No configuration file provided. Starting in memory mode. Remember to save your config!");
            println!("    hint: use command `backing` for help!");
        } else {
            match QuarterbackConfig::from_yaml_file_path(config) {
                None => {
                    panic!("ERROR: Unable to load Yaml file. Exiting.");
                }
                Some(config) => conf = config,
            }
        }

        let mut eval = |input: &str| -> Result<EvalResult<()>, ()> { conf.eval(input) };
        let _ = repl(&mut eval);
    }

    fn daemon(
        config: &str,
        allow_print_config: bool,
        request_logging: bool,
        listen_addr: &str,
        swagger_ui: bool,
        global_rate_limit_secs: u64,
    ) {
        println!("Quarterback Daemon");
        println!();

        let conf = QuarterbackConfig::from_yaml_file_path(config);

        match conf {
            None => panic!("Configuration file required for daemon mode! Provide a configuration with --config someconfig.yml\nConfigure interactively in 'config' mode (default) by removing 'daemon' from the command line!"),
            Some(conf) => {
                let api = Api {
                    admin_key: Uuid::new_v4().to_string(),
                    request_logging,
                    allow_print_config,
                    action_user_map: conf.compute_action_map(),
                    config: conf,
                    rate_limiter: RateLimiting { rate_map: RwLock::new(HashMap::new()) },
                    global_rate_limit_secs,
                    task_manager: TaskManager::new(),
                    //holy ugliness batman
                    action_status: std::sync::Arc::new(RwLock::new(HashMap::new())),
                };

                let url = format!("http://{}", listen_addr);
                if allow_print_config {
                    //println!("Admin key for this run: {}", api.admin_key);
                    println!("Configuration can be printed at: {url}/config/{}", api.admin_key);
                    println!("Current rate limits can be printed at: {url}/config/limits/{}", api.admin_key);
                } else {
                    println!(
                        "Configuration printing disabled. {url}/config routes will not work"
                    );
                    println!("    Enable with --allow-print-config on cmdline");
                }
                let api_service = OpenApiService::new(api, "QuarterbackDaemon", "0.1").server(&url);
                let ui = api_service.swagger_ui();

                //let app = Route::new().nest("/", api_service).nest("/swagger", ui);

                let app = if swagger_ui {
                    Route::new().nest("/", api_service).nest("/swagger", ui)
                } else {
                    Route::new().nest("/", api_service)
                };

                let server = Server::new(TcpListener::bind(listen_addr)).run(app);

                match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Err(e) => panic!("Unable to start tokio! {e}"),
                    Ok(tokio) => {
                        println!("A global rate limit of {} seconds is set for Quarterback. Adjust this with --global-rate-limit-secs", global_rate_limit_secs);
                        println!("Listening at: {url}");
                        if swagger_ui {
                            println!("Swagger UI enabled: {url}/swagger");
                        } else {
                            println!("Swagger UI disabled: Enable it with --with-swagger-ui");
                        }
                        if request_logging {
                            println!("Request logging enabled"); 
                            println!("  Note: Only requests which are handled by Quarterback are logged, routes that '404', or are rate limited are not logged.");
                            println!("  Note: Actions and user IDs are translated to their names in this request log. For 'neural efficiency'");
                            println!("    To capture all/full requests, it is recommended to enable logging in the upstream reverse proxy.");
                        } else {
                            println!("Request logging disabled. No additional output to stdout is expected.");
                            println!("    Enable it with --with-request-logging");
                        }
                        let _ = tokio.block_on(server);
                    }
                }
            }
        }
    }

    fn operate(self, args: Args) {
        match self {
            QuarterbackMode::Config => QuarterbackMode::configurator(&args.config),
            QuarterbackMode::Daemon => QuarterbackMode::daemon(
                &args.config,
                args.allow_print_config,
                args.with_request_logging,
                &args.listen_addr,
                args.with_swagger_ui,
                args.global_rate_limit_secs,
            ),
        }
    }
}
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(default_value = "config")]
    mode: QuarterbackMode,
    #[arg(
        short,
        long,
        default_value = "",
        hide_default_value = true,
        help = "Configuration file (absolute or relative to working directory)"
    )]
    config: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow the config to be output at the /config/:authkey route in daemon mode"
    )]
    allow_print_config: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Log requests to routes handled by Quarterback (not including 404s, or rate limit dropped requests)"
    )]
    with_request_logging: bool,
    #[arg(
        short,
        long,
        default_value = "127.0.0.1:4242",
        help = "Address for daemon to listen on, also used as Swagger UI server base"
    )]
    listen_addr: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Enables the Swagger UI at /swagger in daemon mode"
    )]
    with_swagger_ui: bool,
    #[arg(
        long,
        default_value_t = 5,
        help = "'Global rate limit' for API endpoints. This is used for bruteforce prevention."
    )]
    global_rate_limit_secs: u64,
}

fn main() {
    let args = Args::parse();

    args.mode.operate(args);
}
