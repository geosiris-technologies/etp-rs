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
pub struct GetChannelMetadata {
    #[serde(rename = "uris")]
    pub uris: HashMap<String, String>,
}

fn getchannelmetadata_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetChannelMetadata {
    fn avro_schema(&self) -> Option<Schema> {
        getchannelmetadata_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetChannelMetadata {}

impl AvroDeserializable for GetChannelMetadata {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetChannelMetadata> {
        let record =
            from_avro_datum(&getchannelmetadata_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetChannelMetadata>(&record)
    }
}

impl ETPMetadata for GetChannelMetadata {
    fn protocol(&self) -> i32 {
        21
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

impl GetChannelMetadata {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_GetChannelMetadata(self.clone())
    }
}

impl Default for GetChannelMetadata {
    /* Protocol 21, MessageType : 1 */
    fn default() -> GetChannelMetadata {
        GetChannelMetadata {
            uris: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "GetChannelMetadata",
    "protocol": "21",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uris",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.GetChannelMetadata",
    "depends": []
}"#;
