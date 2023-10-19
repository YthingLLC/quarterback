#![warn(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use std::time::Duration;
//maybe I will use this if I ever care about supporting Windows
//use std::path::Path;

use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
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

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackAction {
    name: String,
    action_path: String,
    action_args: String,
    timeout: Duration,
    cooldown: Duration,
    signal: u8,
    log_stdout: bool,
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
        println!("default false");
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

struct Api {
    admin_key: String,
    config: QuarterbackConfig,
    allow_print_config: bool,
    request_logging: bool,
    action_user_map: QuarterbackActionUsers,
}

#[OpenApi]
impl Api {
    fn get_now(&self) -> String {
        format!("{:?}", chrono::offset::Local::now())
    }
    /// Hello World
    #[oai(path = "/", method = "get")]
    async fn index(&self) -> PlainText<&'static str> {
        if self.request_logging {
            println!("{} GET /", self.get_now());
        }
        PlainText("Hello World")
    }

    #[oai(path = "/config/:authkey", method = "get")]
    async fn print_config(&self, authkey: Path<Option<String>>) -> poem::Result<PlainText<String>> {
        let authkey = match authkey.0 {
            None => "".to_string(),
            Some(key) => key,
        };
        if self.request_logging {
            println!(
                "{} GET /config/{} - allow_print_config: {:?}",
                self.get_now(),
                &authkey,
                &self.allow_print_config
            );
        }
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

    async fn action_run() {}

    async fn action_status() {}

    async fn action_abort() {}

    async fn action_timeout() {}

    async fn action_cooldown() {}

    async fn action_log() {}
}

#[derive(Debug, Copy, Clone, ValueEnum)]
enum QuarterbackMode {
    Config,
    Daemon,
    //TODO: Add eval mode
    //should operate as configurator, but eval only one line
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

    fn daemon(config: &str, allow_print_config: bool, request_logging: bool, listen_addr: &str) {
        println!("Quarterback Daemon");
        println!();

        let conf = QuarterbackConfig::from_yaml_file_path(config);

        match conf {
            None => panic!("Configuration file required for daemon mode!"),
            Some(conf) => {
                let api = Api {
                    admin_key: Uuid::new_v4().to_string(),
                    request_logging,
                    allow_print_config,
                    action_user_map: conf.compute_action_map(),
                    config: conf,
                };
                if allow_print_config {
                    println!("Admin key for this run: {}", api.admin_key);
                    println!(
                        "Configuration can be printed at route: /config/{}",
                        api.admin_key
                    );
                } else {
                    println!(
                        "Configuration printing disabled. /config/:authkey route will not work"
                    );
                    println!("    Enable with --allow-print-config on cmdline");
                }
                let url = format!("http://{}", listen_addr);
                let api_service = OpenApiService::new(api, "QuarterbackDaemon", "0.1").server(&url);
                let ui = api_service.swagger_ui();
                let app = Route::new().nest("/", api_service).nest("/docs", ui);

                let server = Server::new(TcpListener::bind(listen_addr)).run(app);

                match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Err(e) => panic!("Unable to start tokio! {e}"),
                    Ok(tokio) => {
                        println!("Listening at: {url}");
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
            ),
        }
    }
}
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(default_value = "config")]
    mode: QuarterbackMode,
    #[arg(short, long, default_value = "")]
    config: String,
    #[arg(long, default_value_t = false)]
    allow_print_config: bool,
    #[arg(long, default_value_t = false)]
    with_request_logging: bool,
    #[arg(short, long, default_value = "127.0.0.1:4242")]
    listen_addr: String,
}

fn main() {
    let args = Args::parse();

    args.mode.operate(args);
}
