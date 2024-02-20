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
pub struct Ping {
    #[serde(rename = "currentDateTime")]
    pub current_date_time: i64,
}

fn ping_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for Ping {
    fn avro_schema(&self) -> Option<Schema> {
        ping_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for Ping {}

impl AvroDeserializable for Ping {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<Ping> {
        let record = from_avro_datum(&ping_avro_schema().unwrap(), input, None).unwrap();
        from_value::<Ping>(&record)
    }
}

impl ETPMetadata for Ping {
    fn protocol(&self) -> i32 {
        0
    }
    fn message_type(&self) -> i32 {
        8
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

impl Ping {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Core_Ping(self.clone())
    }
}

impl Default for Ping {
    /* Protocol 0, MessageType : 8 */
    fn default() -> Ping {
        Ping {
            current_date_time: time_to_etp(SystemTime::now()),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Core",
    "name": "Ping",
    "protocol": "0",
    "messageType": "8",
    "senderRole": "client,server",
    "protocolRoles": "client, server",
    "multipartFlag": false,
    "fields": [
        {
            "name": "currentDateTime",
            "type": "long"
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Core.Ping",
    "depends": []
}"#;
