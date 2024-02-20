// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
#[allow(unused_imports)]
mod handler;
// use log::{info, trace, warn};

use crate::handler::get_connection;
use crate::handler::get_request_session;
use crate::handler::send_command;
use etptypes::energistics::etp::v12::datatypes::object::data_object::DataObject;
use etptypes::energistics::etp::v12::datatypes::object::resource::Resource;
use etptypes::protocols::ProtocolMessage::*;
use std::fs::File;
use std::path::Path;

use etpproto::connection::EtpConnection;
use etpproto::message::decode_message;
use etptypes::protocols::ProtocolMessage;

use clap::Parser;
use futures::channel;
use futures::stream::SplitStream;
use futures_util::StreamExt;
use http_auth_basic::Credentials;
use std::env;
use std::io::stdin;
use std::io::stdout;
use std::io::{self, Write};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::WebSocketStream;
use tungstenite::{handshake::client::generate_key, http::Request, Message};

#[tokio::main]
async fn main() {
    env::set_var("RUST_BACKTRACE", "full");

    let args = Args::parse();
    println!("{args:?}");
    println!("{:?}", args.url);

    test_tokio(args).await;
}

async fn test_tokio(args: Args) {
    let (tx, rx) = channel::mpsc::unbounded::<tungstenite::protocol::Message>();
    let mut auth: Option<String> = None;
    if let Some(login) = &args.login {
        if let Some(password) = &args.password {
            let credentials = Credentials::new(&login, &password);
            auth = Some(credentials.as_http_header());
        }
    }

    let mut url = format!("{}", args.url);
    if !url.to_lowercase().starts_with("ws:") && !url.to_lowercase().starts_with("wss:") {
        url = "ws://".to_owned() + &url;
    }

    println!("{:?}", auth);
    let request = Request::builder()
        .uri(&url)
        .header("Host", "localhost")
        .header("Authorization", auth.unwrap_or("".to_string()))
        .header("Connection", "upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-Websocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Protocol", "etp12.energistics.org")
        .header("MaxWebSocketFramePayloadSize", "4194304")
        .header("MaxWebSocketMessagePayloadSize", "16777216")
        .body(())
        .unwrap();
    let (ws_stream, response) = connect_async(request).await.expect("Failed connect");
    println!("WebSocket handshake has been completed");
    println!("{}", response.status());

    let mut etp_connection = get_connection();

    let (write, read) = ws_stream.split();

    tokio::spawn(rx.map(Ok).forward(write));

    send_message(
        &tx,
        &mut etp_connection,
        get_request_session().as_protocol_message(),
    )
    .await;

    tokio::spawn(async { receive(read, args).await });
    //tokio::spawn(async { interface(&tx, &mut etp_connection).await });

    interface(&tx, &mut etp_connection).await;
}

async fn send_message(
    tx: &channel::mpsc::UnboundedSender<Message>,
    etp_connection: &mut EtpConnection,
    msg: ProtocolMessage,
) {
    for m in etp_connection.send_encoded(msg, None, None, None).unwrap() {
        let send_message_result = tx.unbounded_send(Message::Binary(m));
        match send_message_result {
            Ok(_) => println!("Sent successfully"),
            Err(e) => println!("{:?}", e),
        }
    }
}

async fn receive(
    mut read: SplitStream<
        WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    >,
    args: Args,
) {
    while let Some(message) = read.next().await {
        match message {
            Ok(msg) => {
                match msg {
                    tungstenite::Message::Binary(b) => {
                        log(&"input Message: ".to_string(), &args.log_file);
                        let decoded_msg = std::panic::catch_unwind(|| decode_message(&b));
                        if let Ok(decoded) = decoded_msg {
                            print_protocol_message(decoded.body.unwrap(), &args);
                        } else if let Err(not_decoded) = decoded_msg {
                            log(
                                &format!(
                                    "ERR) Failed to decode message: {:?}\n{:?}",
                                    not_decoded, b
                                ),
                                &args.log_file,
                            );
                        }
                    }
                    tungstenite::Message::Text(b) => {
                        log(&format!(" TEXT {:?}", b), &args.log_file);
                    }
                    _ => {} /*Nothing to do, it can be a Wesocket ping message (not an ETP one) */
                }
            }
            Err(e) => log(&format!("{}", e), &args.log_file),
        }
    }
    println!("FIN receive");
}

async fn interface(
    tx: &channel::mpsc::UnboundedSender<Message>,
    etp_connection: &mut EtpConnection,
) {
    loop {
        let mut s = String::new();
        print!("Please enter some text: ");
        let _ = stdout().flush();
        stdin()
            .read_line(&mut s)
            .expect("Did not enter a correct string");
        if let Some('\n') = s.chars().next_back() {
            s.pop();
        }
        if let Some('\r') = s.chars().next_back() {
            s.pop();
        }
        println!("You typed: {}", s);

        match get_message_from_user_entry(&s) {
            Some(msg) => send_message(tx, etp_connection, msg).await,
            None => { /*println!("Unrecognized message. Please retry");*/ }
        }
        if etp_connection.is_connected {
            break;
        }
    }
}

fn get_message_from_user_entry(entry: &String) -> Option<ProtocolMessage> {
    let command_and_params: Vec<&str> = entry.split(' ').collect();
    return send_command(command_and_params);
}

#[derive(Parser, Debug)]
#[clap(
    author = "Valentin Gauthier",
    version,
    about = "A simple etpclient that use etpproto"
)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value = None)]
    login: Option<String>,
    #[arg(short, long, default_value = None)]
    password: Option<String>,

    #[arg(long, default_value = None)]
    log_file: Option<String>,
}

fn log(input: &String, out: &Option<String>) {
    let mut out_writer = match out {
        Some(x) => {
            let path = Path::new(&x);
            if path.exists() {
                Box::new(File::options().append(true).open(&path).unwrap()) as Box<dyn Write>
            } else {
                Box::new(File::create(&path).unwrap()) as Box<dyn Write>
            }
        }
        None => Box::new(io::stdout()) as Box<dyn Write>,
    };
    let _ = out_writer.write(input.as_bytes());
    let _ = out_writer.write(b"\n");
}

/*
    ____                  ____     ____       _       __
   / __ \___  _______  __/ / /_   / __ \_____(_)___  / /_
  / /_/ / _ \/ ___/ / / / / __/  / /_/ / ___/ / __ \/ __/
 / _, _/  __(__  ) /_/ / / /_   / ____/ /  / / / / / /_
/_/ |_|\___/____/\__,_/_/\__/  /_/   /_/  /_/_/ /_/\__/
*/

fn print_protocol_message(msg: ProtocolMessage, args: &Args) {
    match msg {
        Discovery_GetResourcesResponse(mut grr) => {
            log(
                &format!("GetRangesResponse : {} entity found", grr.resources.len()),
                &args.log_file,
            );
            grr.resources
                .sort_by(|a, b| a.uri.partial_cmp(&b.uri).unwrap());
            for r in grr.resources {
                log(&format!("{}", format_resource(&r)), &args.log_file);
            }
        }
        Dataspace_GetDataspacesResponse(dsr) => {
            log(
                &format!(
                    "Dataspaces : {:?}",
                    dsr.dataspaces
                        .iter()
                        .map(|d| &d.uri)
                        .collect::<Vec<&String>>()
                ),
                &args.log_file,
            );
        }
        Store_GetDataObjectsResponse(gdo) => {
            for (_, d_o) in &gdo.data_objects {
                log(&format!("{}", format_data_object(&d_o)), &args.log_file);
            }
        }
        _ => {
            log(&format!("{:?}", msg), &args.log_file);
        }
    }
}

fn format_resource(r: &Resource) -> String {
    format!(
        "{:?}: {:?}\n\tsources : {:?}\n\ttargets: {:?}",
        r.name, r.uri, r.source_count, r.target_count
    )
}

fn format_data_object(d_o: &DataObject) -> String {
    format!(
        "{:?}: {:?}\n\tContent : {}\n",
        d_o.resource.uri,
        d_o.format,
        String::from_utf8(d_o.data.to_vec()).unwrap()
    )
}
