// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
use crate::helpers::*;
use apache_avro::{Error, Schema};
use bytes;
use derivative::Derivative;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;
#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct CloseSession {
    #[serde(rename = "reason")]
    #[derivative(Default(value = r#"String::from("")"#))]
    pub reason: String,
}

fn closesession_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for CloseSession {
    fn avro_schema(&self) -> Option<Schema> {
        closesession_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for CloseSession {}

impl AvroDeserializable for CloseSession {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<CloseSession> {
        let record = from_avro_datum(&closesession_avro_schema().unwrap(), input, None).unwrap();
        from_value::<CloseSession>(&record)
    }
}

impl ETPMetadata for CloseSession {
    fn protocol(&self) -> i32 {
        0
    }
    fn message_type(&self) -> i32 {
        5
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Client, Role::Server]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Client, Role::Server]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl CloseSession {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Core_CloseSession(self.clone())
    }
}

impl Default for CloseSession {
    /* Protocol 0, MessageType : 5 */
    fn default() -> CloseSession {
        CloseSession {
            reason: "".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Core",
    "name": "CloseSession",
    "protocol": "0",
    "messageType": "5",
    "senderRole": "client,server",
    "protocolRoles": "client, server",
    "multipartFlag": false,
    "fields": [
        {
            "name": "reason",
            "type": "string",
            "default": ""
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Core.CloseSession",
    "depends": []
}"#;
