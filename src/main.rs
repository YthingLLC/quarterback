#![warn(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};

use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use clap::{Parser, ValueEnum};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use simple_repl::{repl, EvalResult};
use std::fs::File;
use std::io::prelude::*;
//maybe I will use this if I ever care about supporting Windows
//use std::path::Path;
use indoc::printdoc;
use std::time::Duration;
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
    action_path: String,
    action_args: String,
    timeout: Duration,
    cooldown: Duration,
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
                print_if!(print, "Hash: {password_string:?}");

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
               or resetuser             if a key is provided, it will be set to the provided key
                                        Example: resetuser [userid] [userkey (default: new uuid)]

            checkuserkey            check if a key is valid for a user
                                        Example: checkuserkey [userid] [userkey]

            superuser               set or unset the super user flag for a specific user
                                        Example: superuser [userid] [super user flag (default: false)]

            username                set a new name for a userid
                                        Example: username [userid] [name]
                                        See `users` command, user names are not unique.


            addrole                 add a new role
                                        Example: addrole [rolename]
                                        Note: by default, roles are assigned no users or actions

            clonerole               clone a role, and all users and actions assigned to it
                                        Example: clonerole [roleid] 


            addaction               add a new action
                                        Example: addaction [command] [args...]

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


            The following commands are included for testing only. They may be removed at any time:

            [Command]               [Description]
            is_true                 outputs whether the following 'word' evaluates to 'true'
                                        used in other commands to determine flag is true/false

            hash                    hash the next 'word' with argon2id and output the result
                                        used in commands that generate 'keys' to prevent plain
                                        text secrets in the backing stores

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
            Some("adduser") => {
                let name = input_vec.next();
                let super_user = QuarterbackConfig::is_true(input_vec.next());
                if let Some(name) = name {
                    self.add_user(name, super_user);
                } else {
                    println!("ERROR: A user name must be provided.");
                }
            }
            Some("resetuserkey") | Some("resetuser") => {
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
            Some("checkuserkey") => {
                let user = input_vec.next();
                let key = input_vec.next();

                if let (Some(user), Some(key)) = (user, key) {
                    self.check_user_key(user, key);
                } else {
                    println!("ERROR: A userid and key must be provided!");
                    println!("    Example: checkuserkey [userid] [key]");
                }
            }
            Some("superuser") => {
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
            Some("addaction") => {}
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
