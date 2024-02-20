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
pub struct Pong {
    #[serde(rename = "currentDateTime")]
    pub current_date_time: i64,
}

fn pong_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for Pong {
    fn avro_schema(&self) -> Option<Schema> {
        pong_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for Pong {}

impl AvroDeserializable for Pong {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<Pong> {
        let record = from_avro_datum(&pong_avro_schema().unwrap(), input, None).unwrap();
        from_value::<Pong>(&record)
    }
}

impl ETPMetadata for Pong {
    fn protocol(&self) -> i32 {
        0
    }
    fn message_type(&self) -> i32 {
        9
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

impl Pong {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Core_Pong(self.clone())
    }
}

impl Default for Pong {
    /* Protocol 0, MessageType : 9 */
    fn default() -> Pong {
        Pong {
            current_date_time: time_to_etp(SystemTime::now()),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Core",
    "name": "Pong",
    "protocol": "0",
    "messageType": "9",
    "senderRole": "client,server",
    "protocolRoles": "client, server",
    "multipartFlag": false,
    "fields": [
        {
            "name": "currentDateTime",
            "type": "long"
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Core.Pong",
    "depends": []
}"#;
