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
pub struct ChannelsClosed {
    #[serde(rename = "reason")]
    pub reason: String,

    #[serde(rename = "id")]
    pub id: HashMap<String, i64>,
}

fn channelsclosed_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ChannelsClosed {
    fn avro_schema(&self) -> Option<Schema> {
        channelsclosed_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ChannelsClosed {}

impl AvroDeserializable for ChannelsClosed {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ChannelsClosed> {
        let record = from_avro_datum(&channelsclosed_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ChannelsClosed>(&record)
    }
}

impl ETPMetadata for ChannelsClosed {
    fn protocol(&self) -> i32 {
        22
    }
    fn message_type(&self) -> i32 {
        7
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        true
    }
}

impl ChannelsClosed {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelDataLoad_ChannelsClosed(self.clone())
    }
}

impl Default for ChannelsClosed {
    /* Protocol 22, MessageType : 7 */
    fn default() -> ChannelsClosed {
        ChannelsClosed {
            reason: "".to_string(),
            id: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelDataLoad",
    "name": "ChannelsClosed",
    "protocol": "22",
    "messageType": "7",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "reason",
            "type": "string"
        },
        {
            "name": "id",
            "type": {
                "type": "map",
                "values": "long"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelDataLoad.ChannelsClosed",
    "depends": []
}"#;
