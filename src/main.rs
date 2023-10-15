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
    fn check_key(&self, key: &str) -> bool {
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
                return false;
            }
            Ok(_) => {
                print_if!(print, "Valid key");
                return true;
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
                QuarterbackConfigBacking::YamlFile(file) => {}
            },
            Err(e) => println!("Error saving: {e}"),
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

        match QuarterbackConfig::hash(&key) {
            Err(e) => println!("Password hashing failed: {e:?}"),
            Ok(key) => {
                println!("User key updated");
                user.user_key = key;
            }
        }
    }

    fn check_user_key(&self, userid: &str, key: &str) {
        let uuid = parseuuid!(userid, "user id");

        let user = getuser!(self, &uuid);

        user.check_key_print(key, true);
    }

    fn set_super_user(&mut self, userid: &str, flag: bool) {
        let uuid = parseuuid!(userid, "user id");

        let user = getusermut!(self, &uuid);

        user.super_user = flag;

        println!(
            "User: {} [{}] Flag set: {:?}",
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
        self.print_action(&uuid, &action);
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
                                            Creates a user `swoz` that is a super user.

                                        See `users` command, user names are not unique.

                                        !!!SUPER USERS CAN RUN ANY ACTION!!!
                                          !!!NO ROLE CHECKING PERFORMED!!!
                                        A 'key' is generated that is used to authenticate the user

            resetuserkey            reset the userkey for a specific userid
                or resetuser            if a key is provided, it will be set to the provided key
                or userkey              Example: resetuser [userid] [userkey (default: new uuid)]

            checkuserkey            check if a key is valid for a user
                or userkeycheck         Example: checkuserkey [userid] [userkey]

            superuser               set or unset the super user flag for a specific user
                or usersuper            Example: superuser [userid] [super user flag (default: false)]

            username                set a new name for a userid
                                        Example: username [userid] [name]
                                        See `users` command, user names are not unique.


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

            addroleaction           add an action to a role
                                        Example: addroleaction [roleid] [actionid]

            addroleuser             add a user to a role
                                        Example: addroleuser [roleid] [userid]
                                        

            delaction               delete an action
                                        Example: delaction [actionid]

            delroleaction           delete an action from a role
                                        Example: delroleaction [roleid] [actionid]

            delroleuser             delete a user from a role
                                        Example: delroleuser [roleid] [userid]

            deluser                 delete a user
                                        Example: deluser [userid]

            save                    save the configuration
                                        use `backing` to see where the configuration will be saved!

            exit                    exit the configurator, remember to save first!
                or quit
            
            exit!
                or quit!            exit the configurtor, without save checking, just like vim.


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

            show_map                compute the map of actions and their allowed users
                                        printing the map to stdout

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
            Some("addrole") => {}
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

                if let (Some(action), Some(action_log)) = (action, action_log) {
                    //                                          yes, I know.
                    //                                          TODO: Deuglify
                    let action_log = QuarterbackConfig::is_true(Some(action_log));
                    self.set_action_stdout(action, action_log);
                } else {
                    println!("ERROR: An action id and flag must be provided!");
                    println!("    If true, log the action output into memory");
                    println!("    false by default");
                    println!("    Example: actionlog [actionid] [logging flag]");
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
            Some(x) => println!("Unknown command: {x}"),
            None => {}
        }

        println!();

        Ok(EvalResult::Continue)
    }
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
            let mut file = File::open(config);
            match &mut file {
                Err(e) => {
                    println!("Failed to load file: {config} - {e}");
                    println!("Starting in memory mode, remember to save your config!");
                    println!("    hint: use command `backing` for help!");
                    conf = QuarterbackConfig::new();
                }
                Ok(file) => {
                    let mut conf_string = String::new();
                    let _ = file.read_to_string(&mut conf_string);
                    let yaml_config = QuarterbackConfig::from_yaml(&conf_string);
                    match yaml_config {
                        Err(e) => panic!("Failed to load yaml: {e}"),
                        Ok(yaml_config) => conf = yaml_config,
                    }
                }
            }
        }

        let mut eval = |input: &str| -> Result<EvalResult<()>, ()> { conf.eval(input) };
        let _ = repl(&mut eval);
    }

    fn operate(self, config: String) {
        match self {
            QuarterbackMode::Config => QuarterbackMode::configurator(&config),
            QuarterbackMode::Daemon => println!("not yet implemented"),
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
}

fn main() {
    let args = Args::parse();

    QuarterbackMode::operate(args.mode, args.config);
}
