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
use uuid::Uuid;

macro_rules! print_if {
    ($should_print:expr, $($arg:tt)*) => {
        if $should_print {
            println!($($arg)*);
        }
    }
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
    role_id: Uuid,
    role_name: String,
    allowed_actions: HashSet<Uuid>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackAction {
    action_id: Uuid,
    action_path: String,
    action_args: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackActions {}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum QuarterbackConfigBacking {
    Memory,
    YamlFile(YamlFileConfig),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct YamlFileConfig {
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

    pub fn to_yaml(&self) {
        let yaml = serde_yaml::to_string(&self);
        match yaml {
            Ok(yaml) => println!("{yaml}"),
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
            println!("    backing set memory");
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
            Some("save") => self.to_yaml(),
            Some("backing") => self.backing(&mut input_vec),
            Some("is_true") => {
                println!("{:?}", QuarterbackConfig::is_true(input_vec.next()));
            }
            Some("hash") => {
                let _ = QuarterbackConfig::hash_with_print(input_vec.next().unwrap_or(""), true);
            }
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
    fn configurator() {
        println!("Quarterback Configurator:");
        println!();

        //hash_password(Uuid::new_v4().to_string().as_str());

        //let password_hash = argon2.hash
        let mut conf = QuarterbackConfig::new();
        let mut eval = |input: &str| -> Result<EvalResult<()>, ()> { conf.eval(input) };
        let _ = repl(&mut eval);
    }

    fn operate(self) {
        match self {
            QuarterbackMode::Config => QuarterbackMode::configurator(),
            QuarterbackMode::Daemon => println!("not yet implemented"),
        }
    }
}
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(default_value = "config")]
    mode: QuarterbackMode,
}

fn main() {
    let args = Args::parse();

    QuarterbackMode::operate(args.mode);
}
