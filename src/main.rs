
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use sha2::Sha256;
use hmac::{Hmac, KeyInit, Mac};
use clap::Parser;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, SurgeError};
use surge_ping::IcmpPacket::{V4, V6};
use thiserror::Error;
use tokio::{io, join};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Error)]
enum CheckHostError {
    #[error("connection error")]
    ConnectionError(#[from] io::Error),
}

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs(seconds))
}

#[derive(Parser, Debug)]
#[command(name = "Network Status Bot")]
#[command(version = "1.0")]
#[command(about = "Check HCSO is available and post message to Feishu", long_about = None)]
struct Cli {
    #[arg(short, long)]
    address: IpAddr,
    #[arg(short, long, value_parser = parse_duration, default_value = "1")]
    timeout: Duration,
    #[arg(short, long, default_value = "0.9")]
    ratio: f32,
    #[arg(long, default_value = "60")]
    window: i32,
    #[command(flatten)]
    lark: LarkClient,
}

#[derive(Debug, Parser)]
struct LarkClient {
    #[arg(short, long)]
    webhook: String,
    #[arg(short, long)]
    secret: String,
}

#[derive(Debug, Error)]
enum WebHookError {
    #[error("reqwest error: {0:?}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("status error: {1}")]
    StatusError(StatusCode, String),
    #[error("serde error: {0:?}")]
    SerdeError(#[from] serde_json::Error),
}

impl LarkClient {
    async fn send_message(&self, msg: &LarkMessage) -> Result<(), WebHookError> {
        let mut body = serde_json::to_value(msg)
            .map_err(WebHookError::from)?;
        let sign = serde_json::to_value(self.sign())
            .map_err(WebHookError::from)?;
        Self::merge(&mut body, sign);
        let resp = reqwest::Client::default()
            .post(&self.webhook)
            .json(&body)
            .send()
            .await
            .map_err(WebHookError::from)?;
        let status = resp.status();
        let resp_body = match resp.json::<Value>().await {
            Ok(v) => v.to_string(),
            Err(e) => e.to_string()
        };
        if status.is_success() {
            tracing::trace!("send message success: {}", resp_body);
            Ok(())
        } else {
            Err(WebHookError::StatusError(status, resp_body))
        }
    }

    fn merge(a: &mut Value, b: Value) {
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                for (k, v) in b {
                    Self::merge(a.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
            (a, b) => *a = b.clone(),
        }
    }

    fn sign(&self) -> Signature {
        let timestamp = chrono::Utc::now().timestamp();
        let string_to_sign = format!("{}\n{}", timestamp, self.secret);
        let mut mac = Hmac::<Sha256>::new_from_slice(string_to_sign.as_bytes()).unwrap();
        mac.update(&[]);
        let sign_data = mac.finalize();
        let sign = STANDARD.encode(sign_data.into_bytes());
        Signature {
            timestamp: timestamp.to_string(),
            sign
        }
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("ping error")]
    Ping(#[from] SurgeError),
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let client = Client::new(&Config::new())
        .map_err(Error::from)?;
    let mut pinger = client.pinger(cli.address, PingIdentifier(11451)).await;

    let fail_ratio = 1.0 - cli.ratio;
    let mut last_status = false;
    let mut accumulator = 0f32;
    let mut seq: u16 = 0;
    loop {
        if accumulator > cli.window as f32 {
            accumulator = cli.window as f32;
        } else if -accumulator > cli.window as f32 {
            accumulator = -cli.window as f32;
        }
        let check = async {
            match pinger.ping(PingSequence(seq), &[0; 8]).await {
                Ok((packet, duration)) => {
                    let bytes = match packet {
                        V4(ref pck) => pck.get_size(),
                        V6(ref pck) => pck.get_size()
                    };
                    tracing::trace!("{} bytes from {}: icmp_seq={} time={:?}",
                             bytes,
                             cli.address,
                             packet.get_sequence(),
                             duration);
                    accumulator += 1.0;
                },
                Err(err) => {
                    tracing::trace!("error: {}", err);
                    accumulator -= 1.0 / fail_ratio;
                }
            }
        };
        join!(
            check,
            tokio::time::sleep(cli.timeout)
        );
        seq += 1;

        tracing::info!("accumulator: {}", accumulator);
        let status = accumulator > 0.0;
        if status == last_status { continue; }
        last_status = status;
        if status {
            tracing::info!("{} server is available", cli.address);
            let res = cli.lark
                .send_message(&LarkMessage::Text {
                    text: format!("{} server is available", cli.address)
                }).await;

            if let Err(e) = res {
                tracing::error!("send message error: {}", e);
            }
        } else {
            tracing::error!("{} server is unavailable", cli.address);
            let res = cli.lark
                .send_message(&LarkMessage::Text {
                    text: format!("{} server is unavailable", cli.address)
                }).await;
            if let Err(e) = res {
                tracing::error!("send message error: {}", e);
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "msg_type", content = "content")]
enum LarkMessage {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "post")]
    Post { post: BTreeMap<String, LarkMessagePost> }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
struct Signature {
    timestamp: String,
    sign: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
struct LarkMessagePost {
    title: String,
    content: Vec<LarkMessageParagraph>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag")]
enum LarkMessageParagraph {
    #[serde(rename = "text")]
    Text { text: String, un_escape: Option<bool> },
    #[serde(rename = "a")]
    Link { text: String, href: String },
    #[serde(rename = "at")]
    At { user_id: String, user_name: Option<String> },
    #[serde(rename = "img")]
    Image { image_key: String }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use crate::{LarkMessage, LarkMessageParagraph, LarkMessagePost};

    #[test]
    fn text_codec() {
        let txt = LarkMessage::Text {
            text: "test".to_string()
        };

        let json = serde_json::to_string(&txt).unwrap();
        assert_eq!(json, r#"{"msg_type":"test","content":{"text":"test"}}"#);
    }

    #[test]
    fn paragraph_codec() {
        let txt = LarkMessage::Post {
            post: BTreeMap::from([
                ("zh_cn".to_string(), LarkMessagePost {
                    title: "".to_string(),
                    content: vec![
                        LarkMessageParagraph::Text {
                            text: "test".to_string(),
                            un_escape: None
                        }
                    ]
                })
            ])
        };

        let json = serde_json::to_string(&txt).unwrap();
        let decoded: LarkMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, txt);
    }
}