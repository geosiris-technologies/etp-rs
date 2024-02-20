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
pub struct Acknowledge {}

fn acknowledge_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for Acknowledge {
    fn avro_schema(&self) -> Option<Schema> {
        acknowledge_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for Acknowledge {}

impl AvroDeserializable for Acknowledge {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<Acknowledge> {
        let record = from_avro_datum(&acknowledge_avro_schema().unwrap(), input, None).unwrap();
        from_value::<Acknowledge>(&record)
    }
}

impl ETPMetadata for Acknowledge {
    fn protocol(&self) -> i32 {
        0
    }
    fn message_type(&self) -> i32 {
        1001
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::All]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Client, Role::Server]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl Acknowledge {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Core_Acknowledge(self.clone())
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Core",
    "name": "Acknowledge",
    "protocol": "0",
    "messageType": "1001",
    "senderRole": "*",
    "protocolRoles": "client, server",
    "multipartFlag": false,
    "fields": [],
    "fullName": "Energistics.Etp.v12.Protocol.Core.Acknowledge",
    "depends": []
}"#;
