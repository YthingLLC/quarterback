#![warn(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{HashMap, HashSet};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use simple_repl::{repl, EvalResult};
use uuid::Uuid;

//this should always contain a valid argon2 hash
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct PasswordString(String);

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackUser {
    user_id: Uuid,
    user_name: String,
    user_key: PasswordString,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackUsers {}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackRole {
    role_id: Uuid,
    role_name: String,
    allowed_actions: HashSet<Uuid>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackRoles {}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackAction {
    action_id: Uuid,
    action_path: String,
    action_args: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackActions {}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackConfig {
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
            users: HashMap::new(),
            roles: HashMap::new(),
            actions: HashMap::new(),
        }
    }

    fn print_users(&self) {
        println!("Users");
        println!();
        println!("{:?}", self.users);
    }

    fn add_user(&mut self, name: &str) {
        let user_id = Uuid::new_v4();
        let user_name = name.to_string();
        let key = Uuid::new_v4().to_string();
        println!("User Config:");
        println!("User ID:   {user_id}");
        println!("User Name: {user_name}");
        println!("User Key:  {key}");

        let key = QuarterbackConfig::hash(&key);
        match key {
            Ok(user_key) => {
                self.users.insert(
                    user_id,
                    QuarterbackUser {
                        user_id,
                        user_name,
                        user_key,
                    },
                );
            }
            Err(e) => {
                println!("Error creating user: {e:?}");
            }
        }
    }

    fn hash(password: &str) -> Result<PasswordString, QuarterbackError> {
        let mut password: String = password.to_string();
        if password.is_empty() {
            password = Uuid::new_v4().to_string();
            println!("No password provided, generating a new UUID as password: {password}")
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
                println!("Hash: {password_string:?}");

                let password_check = Argon2::default().verify_password(password, &x);

                println!("Check: {password_check:?}");
                Ok(PasswordString(password_string))
            }
            Err(e) => {
                println!("Password hashing failed: {e}");
                Err(QuarterbackError::HashError(e))
            }
        }
    }

    fn eval(&mut self, input: &str) -> Result<EvalResult<()>, ()> {
        let mut input_vec = input.trim_end().split(' ');

        let cmd = input_vec.next();

        match cmd {
            Some("version") | Some("v") => println!("Version: {}", env!("CARGO_PKG_VERSION")),
            Some("users") | Some("u") => self.print_users(),
            Some("adduser") => {
                let name = input_vec.next();
                if let Some(name) = name {
                    self.add_user(&name);
                } else {
                    println!("ERROR: A user name must be provided.");
                }
            }
            Some("hash") => {
                let _ = QuarterbackConfig::hash(input_vec.next().unwrap_or(""));
            }
            Some(x) => println!("Unknown command: {x}"),
            None => {}
        }

        println!();

        Ok(EvalResult::Continue)
    }
}

fn main() {
    println!("Quarterback Configurator:");
    println!();

    //hash_password(Uuid::new_v4().to_string().as_str());

    //let password_hash = argon2.hash
    let mut conf = QuarterbackConfig::new();
    let mut eval = |input: &str| -> Result<EvalResult<()>, ()> { conf.eval(input) };
    let _ = repl(&mut eval);
}
