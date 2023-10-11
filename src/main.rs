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
struct QuarterbackUsers {
    users: HashMap<Uuid, QuarterbackUser>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackRole {
    role_id: Uuid,
    role_name: String,
    allowed_actions: HashSet<Uuid>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackRoles {
    roles: HashMap<Uuid, QuarterbackRole>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackAction {
    action_id: Uuid,
    action_path: String,
    action_args: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct QuarterbackActions {
    actions: HashMap<Uuid, QuarterbackAction>,
}

#[derive(Debug)]
struct QuarterbackConfig {}

fn hash_password(password: &str) {
    let mut password: String = password.to_string();
    if password.is_empty() {
        password = Uuid::new_v4().to_string();
        println!("No password provided, generating a new UUID as password: {password}")
    } else {
        println!("Input: {password}");
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
        }
        Err(e) => {
            println!("Password hashing failed: {e}");
        }
    }
}

fn print_users() {
    println!("Users");
}

fn main() {
    println!("Quarterback Configurator:");
    println!();

    //hash_password(Uuid::new_v4().to_string().as_str());

    //let password_hash = argon2.hash
    let _ = repl(eval);
}

fn eval(input: &str) -> Result<EvalResult<()>, ()> {
    let mut input_vec = input.trim_end().split(' ');

    let cmd = input_vec.next();

    match cmd {
        Some("version") | Some("v") => println!("Version: {}", env!("CARGO_PKG_VERSION")),
        Some("users") | Some("u") => print_users(),
        Some("hash") => hash_password(input_vec.next().unwrap_or("")),
        Some(x) => println!("Unknown command: {x}"),
        None => {}
    }

    println!();

    Ok(EvalResult::Continue)
}
