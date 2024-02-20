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

use crate::energistics::etp::v12::datatypes::channel_data::truncate_info::TruncateInfo;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct ChannelsTruncated {
    #[serde(rename = "channels")]
    pub channels: Vec<TruncateInfo>,

    #[serde(rename = "changeTime")]
    pub change_time: i64,
}

fn channelstruncated_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ChannelsTruncated {
    fn avro_schema(&self) -> Option<Schema> {
        channelstruncated_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ChannelsTruncated {}

impl AvroDeserializable for ChannelsTruncated {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ChannelsTruncated> {
        let record =
            from_avro_datum(&channelstruncated_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ChannelsTruncated>(&record)
    }
}

impl ETPMetadata for ChannelsTruncated {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        13
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl ChannelsTruncated {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_ChannelsTruncated(self.clone())
    }
}

impl Default for ChannelsTruncated {
    /* Protocol 21, MessageType : 13 */
    fn default() -> ChannelsTruncated {
        ChannelsTruncated {
            channels: vec![],
            change_time: time_to_etp(SystemTime::now()),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "ChannelsTruncated",
    "protocol": "21",
    "messageType": "13",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "channels",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                    "name": "TruncateInfo",
                    "fields": [
                        {
                            "name": "channelId",
                            "type": "long"
                        },
                        {
                            "name": "newEndIndex",
                            "type": {
                                "type": "record",
                                "namespace": "Energistics.Etp.v12.Datatypes",
                                "name": "IndexValue",
                                "fields": [
                                    {
                                        "name": "item",
                                        "type": [
                                            "null",
                                            "long",
                                            "double",
                                            {
                                                "type": "record",
                                                "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                                                "name": "PassIndexedDepth",
                                                "fields": [
                                                    {
                                                        "name": "pass",
                                                        "type": "long"
                                                    },
                                                    {
                                                        "name": "direction",
                                                        "type": {
                                                            "type": "enum",
                                                            "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                                                            "name": "PassDirection",
                                                            "symbols": [
                                                                "Up",
                                                                "HoldingSteady",
                                                                "Down"
                                                            ],
                                                            "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.PassDirection",
                                                            "depends": []
                                                        }
                                                    },
                                                    {
                                                        "name": "depth",
                                                        "type": "double"
                                                    }
                                                ],
                                                "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.PassIndexedDepth",
                                                "depends": [
                                                    "Energistics.Etp.v12.Datatypes.ChannelData.PassDirection"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "fullName": "Energistics.Etp.v12.Datatypes.IndexValue",
                                "depends": [
                                    "Energistics.Etp.v12.Datatypes.ChannelData.PassIndexedDepth"
                                ]
                            }
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.TruncateInfo",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.IndexValue"
                    ]
                }
            }
        },
        {
            "name": "changeTime",
            "type": "long"
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.ChannelsTruncated",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.TruncateInfo"
    ]
}"#;
