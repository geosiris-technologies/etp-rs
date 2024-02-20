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
pub struct StartStreaming {}

fn startstreaming_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for StartStreaming {
    fn avro_schema(&self) -> Option<Schema> {
        startstreaming_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for StartStreaming {}

impl AvroDeserializable for StartStreaming {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<StartStreaming> {
        let record = from_avro_datum(&startstreaming_avro_schema().unwrap(), input, None).unwrap();
        from_value::<StartStreaming>(&record)
    }
}

impl ETPMetadata for StartStreaming {
    fn protocol(&self) -> i32 {
        1
    }
    fn message_type(&self) -> i32 {
        3
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Consumer]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Producer, Role::Consumer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl StartStreaming {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelStreaming_StartStreaming(self.clone())
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelStreaming",
    "name": "StartStreaming",
    "protocol": "1",
    "messageType": "3",
    "senderRole": "consumer",
    "protocolRoles": "producer,consumer",
    "multipartFlag": false,
    "fields": [],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelStreaming.StartStreaming",
    "depends": []
}"#;
