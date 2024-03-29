// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_variables)]
#![allow(dead_code)]

use etpproto::message::*;
use etptypes::energistics::etp::v12::datatypes::message_header::MessageHeader;
use etptypes::energistics::etp::v12::datatypes::protocol::Protocol;
use etptypes::energistics::etp::v12::datatypes::supported_protocol::SupportedProtocol;
use etptypes::energistics::etp::v12::datatypes::uuid::random_uuid;
use etptypes::energistics::etp::v12::protocol::core::protocol_exception::ProtocolException;
use etptypes::error::eunsupported_protocol;
use etptypes::helpers::AvroDeserializable;
use etptypes::helpers::AvroSerializable;

use etptypes::energistics::etp::v12::protocol::core::pong::Pong;
use etptypes::energistics::etp::v12::protocol::core::request_session::RequestSession;
use etptypes::helpers::time_to_etp;

use etptypes::helpers::ETP12VERSION;
use etptypes::protocols::ProtocolMessage;
use std::collections::HashMap;
use std::time::SystemTime;

/* HANDLER */
struct MyHandler {}

impl EtpMessageHandler for MyHandler {
    fn handle(
        &mut self,
        header: MessageHeaderFlag,
        msg: &ProtocolMessage,
    ) -> Option<Vec<ProtocolMessage>> {
        println!("{:?} <=== ", msg);
        match msg {
            ProtocolMessage::Core_Ping(ping) => Some(vec![Pong::default().as_protocol_message()]),
            ProtocolMessage::Core_Pong(pong) => None,
            _ => Some(vec![ProtocolMessage::Core_ProtocolException(
                ProtocolException::default_with_params(Some(eunsupported_protocol())),
            )]),
        }
    }
}
/* OBJECTS */

fn get_request_session() -> RequestSession {
    let protocols: Vec<SupportedProtocol> = vec![
        SupportedProtocol {
            protocol: Protocol::Core as i32,
            protocol_version: ETP12VERSION,
            role: "Server".to_string(),
            protocol_capabilities: HashMap::new(),
        },
        SupportedProtocol {
            protocol: 3,
            protocol_version: ETP12VERSION,
            role: "Server".to_string(),
            protocol_capabilities: HashMap::new(),
        },
        SupportedProtocol {
            protocol: 4,
            protocol_version: ETP12VERSION,
            role: "Server".to_string(),
            protocol_capabilities: HashMap::new(),
        },
    ];

    let now: SystemTime = SystemTime::now();

    RequestSession {
        application_name: "etp-rs Client Library Application".to_string(),
        application_version: "0.1".to_string(),
        client_instance_id: random_uuid(),
        requested_protocols: protocols,
        supported_data_objects: vec![],
        supported_compression: vec!["gzip".to_string()],
        supported_formats: vec!["xml".to_string(), "json".to_string()],
        current_date_time: time_to_etp(now),
        earliest_retained_change_time: time_to_etp(now),
        server_authorization_required: false,
        endpoint_capabilities: HashMap::new(),
    }
}
/* ------- */

#[test]
fn test_avro_serialization_mh() {
    let header = MessageHeader {
        protocol: 0,
        message_type: 1,
        correlation_id: 52,
        message_id: 51,
        message_flags: 19,
    };
    let hdr_encoded = header.avro_serialize().unwrap();

    let expected: Vec<u8> = vec![0, 2, 104, 102, 38];
    assert_eq!(hdr_encoded, expected);
}

#[test]
fn test_avro_serialization_() {
    let req_sess = get_request_session();
    let record_a = req_sess.avro_serialize();
    match record_a {
        Err(ref e) => println!("{}", e),
        _ => {}
    }
    let record = record_a.unwrap();
    let mut record_slice = record.as_slice();

    assert_eq!(
        req_sess,
        RequestSession::avro_deserialize(&mut record_slice).unwrap()
    )
}
