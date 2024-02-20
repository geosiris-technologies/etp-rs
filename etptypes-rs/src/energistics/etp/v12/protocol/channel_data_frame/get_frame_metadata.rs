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
pub struct GetFrameMetadata {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "includeAllChannelSecondaryIndexes")]
    #[derivative(Default(value = "false"))]
    pub include_all_channel_secondary_indexes: bool,
}

fn getframemetadata_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetFrameMetadata {
    fn avro_schema(&self) -> Option<Schema> {
        getframemetadata_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetFrameMetadata {}

impl AvroDeserializable for GetFrameMetadata {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetFrameMetadata> {
        let record =
            from_avro_datum(&getframemetadata_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetFrameMetadata>(&record)
    }
}

impl ETPMetadata for GetFrameMetadata {
    fn protocol(&self) -> i32 {
        2
    }
    fn message_type(&self) -> i32 {
        1
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Customer]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl GetFrameMetadata {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelDataFrame_GetFrameMetadata(self.clone())
    }
}

impl GetFrameMetadata {
    /* Protocol 2, MessageType : 1 */
    pub fn default_with_params(uri: String) -> GetFrameMetadata {
        GetFrameMetadata {
            uri,
            include_all_channel_secondary_indexes: false,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelDataFrame",
    "name": "GetFrameMetadata",
    "protocol": "2",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "includeAllChannelSecondaryIndexes",
            "type": "boolean",
            "default": false
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelDataFrame.GetFrameMetadata",
    "depends": []
}"#;
