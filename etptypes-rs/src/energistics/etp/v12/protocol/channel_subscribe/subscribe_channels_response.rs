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
pub struct SubscribeChannelsResponse {
    #[serde(rename = "success")]
    pub success: HashMap<String, String>,
}

fn subscribechannelsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for SubscribeChannelsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        subscribechannelsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for SubscribeChannelsResponse {}

impl AvroDeserializable for SubscribeChannelsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<SubscribeChannelsResponse> {
        let record = from_avro_datum(
            &subscribechannelsresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<SubscribeChannelsResponse>(&record)
    }
}

impl ETPMetadata for SubscribeChannelsResponse {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        12
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

impl SubscribeChannelsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_SubscribeChannelsResponse(self.clone())
    }
}

impl Default for SubscribeChannelsResponse {
    /* Protocol 21, MessageType : 12 */
    fn default() -> SubscribeChannelsResponse {
        SubscribeChannelsResponse {
            success: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "SubscribeChannelsResponse",
    "protocol": "21",
    "messageType": "12",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "success",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.SubscribeChannelsResponse",
    "depends": []
}"#;
