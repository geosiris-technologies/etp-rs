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

use crate::energistics::etp::v12::datatypes::channel_data::channel_change_request_info::ChannelChangeRequestInfo;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetChangeAnnotations {
    #[serde(rename = "channels")]
    pub channels: HashMap<String, ChannelChangeRequestInfo>,

    #[serde(rename = "latestOnly")]
    #[derivative(Default(value = "false"))]
    pub latest_only: bool,
}

fn getchangeannotations_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetChangeAnnotations {
    fn avro_schema(&self) -> Option<Schema> {
        getchangeannotations_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetChangeAnnotations {}

impl AvroDeserializable for GetChangeAnnotations {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetChangeAnnotations> {
        let record =
            from_avro_datum(&getchangeannotations_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetChangeAnnotations>(&record)
    }
}

impl ETPMetadata for GetChangeAnnotations {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        14
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

impl GetChangeAnnotations {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_GetChangeAnnotations(self.clone())
    }
}

impl Default for GetChangeAnnotations {
    /* Protocol 21, MessageType : 14 */
    fn default() -> GetChangeAnnotations {
        GetChangeAnnotations {
            channels: HashMap::new(),
            latest_only: false,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "GetChangeAnnotations",
    "protocol": "21",
    "messageType": "14",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "channels",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                    "name": "ChannelChangeRequestInfo",
                    "fields": [
                        {
                            "name": "sinceChangeTime",
                            "type": "long"
                        },
                        {
                            "name": "channelIds",
                            "type": {
                                "type": "array",
                                "items": "long"
                            }
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.ChannelChangeRequestInfo",
                    "depends": []
                }
            }
        },
        {
            "name": "latestOnly",
            "type": "boolean",
            "default": false
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.GetChangeAnnotations",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.ChannelChangeRequestInfo"
    ]
}"#;
