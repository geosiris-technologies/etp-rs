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
pub struct TruncateChannelsResponse {
    #[serde(rename = "channelsTruncatedTime")]
    pub channels_truncated_time: HashMap<String, i64>,
}

fn truncatechannelsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for TruncateChannelsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        truncatechannelsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for TruncateChannelsResponse {}

impl AvroDeserializable for TruncateChannelsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<TruncateChannelsResponse> {
        let record = from_avro_datum(
            &truncatechannelsresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<TruncateChannelsResponse>(&record)
    }
}

impl ETPMetadata for TruncateChannelsResponse {
    fn protocol(&self) -> i32 {
        22
    }
    fn message_type(&self) -> i32 {
        10
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

impl TruncateChannelsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelDataLoad_TruncateChannelsResponse(self.clone())
    }
}

impl Default for TruncateChannelsResponse {
    /* Protocol 22, MessageType : 10 */
    fn default() -> TruncateChannelsResponse {
        TruncateChannelsResponse {
            channels_truncated_time: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelDataLoad",
    "name": "TruncateChannelsResponse",
    "protocol": "22",
    "messageType": "10",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "channelsTruncatedTime",
            "type": {
                "type": "map",
                "values": "long"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelDataLoad.TruncateChannelsResponse",
    "depends": []
}"#;
