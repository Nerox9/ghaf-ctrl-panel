/*
 * Based on https://github.com/vadika/rust-bugreporter
 */

use base64::Engine;
use chrono::Utc;
use gtk::{Label, TemplateChild};
use gtk::prelude::WidgetExt;
use octocrab::Octocrab;
use regex::Regex;
use serde::Deserialize;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::process::Stdio;
use std::io::Write;
use tokio::io::{BufReader, AsyncBufReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
#[derive(Debug, Deserialize, Clone)]
pub struct GithubConfig {
    pub token: String,
    pub owner: String,
    pub repo: String,
}

pub static CONFIG: OnceLock<GithubConfig> = OnceLock::new();

pub fn get_config_path() -> String {
    let variable_name = "GITHUB_CONFIG";
    let variable = env::var(variable_name);
    let path = match variable {
        Ok(ref val) => val,
        Err(e) => {
            println!("Missing environment variable: {}, {}", variable_name, e);
            "/home/ghaf/.config/ctrl-panel/config.toml"
        }
    };
    path.to_string()
}

pub fn load_config() -> Result<GithubConfig, String> {
    let path = get_config_path();

    let config = match config::Config::builder()
        .add_source(config::File::from(PathBuf::from(path)))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err("Failed to load config".to_string()),
    };

    let result = match config.try_deserialize::<GithubConfig>() {
        Ok(r) => r,
        Err(e) => return Err("Failed to parse config".to_string()),
    };

    Ok(result)
}

pub fn update_config_file(token: &str) -> std::io::Result<()> {
    let mut token_old = String::new();
    let path = get_config_path();
    let contents = fs::read_to_string(path.clone())?;
    let expression = Regex::new(r#"token =(\s+\S+)"#).unwrap();
    for cap in expression.captures_iter(&contents) {
        token_old = cap[1].to_string(); 
    }

    println!("CONFIG_PATH: {} OLD_TOKEN: {}", path, token_old);
    let new = contents.replace(&token_old, format!("\"{token}\"").as_str());
    dbg!(&contents, &new);

    let mut file = fs::OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write(new.as_bytes())?;

    Ok(())
}

pub async fn login_start() -> Result<String, Box<dyn std::error::Error>> {
    let mut code = String::new();
    let github_auth_process = Command::new("gh")
                .arg("auth")
                .arg("login")
                .arg("-w")
                .arg("-p")
                .arg("https")
                .env("PATH", "/usr/bin") // TODO: change
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

    match github_auth_process {
        Ok(mut process) => {
            let stdin = process.stdin.take().unwrap();
            let stdout = process.stdout.take().unwrap();
            let stderr = process.stderr.take().unwrap();
            let mut buffer = BufReader::new(stderr).lines();


            tokio::spawn(async move {
                let status = process.wait().await
                    .expect("child process encountered an error");
                println!("child status was: {}", status);
            });

            while let Some(line) = buffer.next_line().await.expect("Github doesn't response") {
                println!("Stderr line: {}", line);
                let parts = line.split("one-time code: ");
                if parts.clone().count() > 1 {
                    match parts.last() {
                        Some(c) => { code = c.clone().to_string(); break; },
                        None => { eprintln!("One-time code is missing"); },
                    };
                }
                
            };
        },
        Err(e) => {
            eprintln!("Failed to fetch Github token: {}", e);
            return Err("Failed to fetch Github token: {e}".into());
        }
    };

    Ok(code)
}

pub async fn login(
) -> Result<(String, Child), Box<dyn std::error::Error>> {
    let mut github_child: Child;
    let mut code: String = String::new();
    let github_auth_process = Command::new("gh")
                .arg("auth")
                .arg("login")
                .arg("-w")
                .arg("-p")
                .arg("https")
                .env("PATH", "/usr/bin") // TODO: change
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

    match github_auth_process {
        Ok(mut process) => {
            let stdin = process.stdin.take().unwrap();
            let stdout = process.stdout.take().unwrap();
            let stderr = process.stderr.take().unwrap();

            let mut buffer = BufReader::new(stderr).lines();
        
            
            /*tokio::spawn(async move {
                let status = process.wait().await
                    .expect("child process encountered an error");
                println!("child status was: {}", status);
            });*/

            while let Some(line) = buffer.next_line().await.expect("Github doesn't response") {
                println!("Stderr line: {}", line);
                let parts = line.split("one-time code: ");
                if parts.clone().count() > 1 {
                    match parts.last() {
                        Some(c) => { code = c.clone().to_string(); break; },
                        None => { eprintln!("One-time code is missing"); },
                    };
                }
                
            };

            println!("Code: {:?}", code);
            std::process::Command::new("xdg-open").env("PATH", "/usr/bin").arg("https://github.com/login/device").output();
            github_child = process;
        }
        Err(e) => {
            eprintln!("Failed to fetch Github token: {}", e);
            return Err("Failed to fetch Github token: {e}".into());
        }
    }

    Ok((code, github_child))
}

pub fn get_token() -> Option<String> {
    let account_raw = std::process::Command::new("gh")
                .arg("auth")
                .arg("status")
                .arg("--show-token")
                .env("PATH", "/usr/bin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output();

    let account = match account_raw {
        Ok(output) => {
            let token = if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.into_owned()
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("gh auth status error: {}", stderr);
                return None
            };
            token
        }
        Err(e) => {
            eprintln!("Failed to execute gh auth status: {}", e);
            return None
        }
    };

    let mut token = String::new();
    let account_parts = account.split("Token: ");
    match account_parts.last() {
        Some(t) => { for line in t.lines() {
                token = line.clone().to_string();
                break;
            } 
        },
        _ => return None,
    };
    
    Some(token)
}

pub fn set_config() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match load_config() {
        Ok(c) => CONFIG.set(c),
        Err(e) => return Err(e.into()),
    };
    Ok(())
}

pub async fn create_github_issue(
    title: &str,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let settings = CONFIG.get().unwrap();

    let octocrab = Octocrab::builder()
        .personal_token(settings.token.clone())
        .build()?;

    let parts: Vec<&str> = content.split("\n\nAttachment:").collect();
    let (issue_body, attachment_info) = (parts[0], parts.get(1));

    let mut final_body = issue_body.to_string();

    if let Some(attachment_text) = attachment_info {
        if let Some(base64_start) = attachment_text.find("Base64 Data:\n") {
            let base64_data = &attachment_text[base64_start + 12..];
            let image_data =
                base64::engine::general_purpose::STANDARD.decode(base64_data.trim())?;

            let timestamp = Utc::now().timestamp();
            let filename = format!("screenshot_{}.png", timestamp);

            let route = format!(
                "/repos/{}/{}/contents/{}",
                settings.owner, settings.repo, filename
            );

            let encoded_content = base64::engine::general_purpose::STANDARD.encode(&image_data);

            let body = serde_json::json!({
                "message": "Add screenshot for bug report",
                "content": encoded_content
            });

            let response = octocrab._put(route, Some(&body)).await?;

            if response.status().is_success() {
                let bytes = hyper::body::to_bytes(response.into_body()).await?;
                let file_info: serde_json::Value = serde_json::from_slice(&bytes)?;
                if let Some(content) = file_info.get("content") {
                    if let Some(download_url) = content.get("download_url").and_then(|u| u.as_str())
                    {
                        final_body.push_str(&format!("\n\n![Screenshot]({})", download_url));
                    }
                }
            }
        }
    }

    octocrab
        .issues(&settings.owner, &settings.repo)
        .create(title)
        .body(&final_body)
        .send()
        .await?;

    Ok(())
}
