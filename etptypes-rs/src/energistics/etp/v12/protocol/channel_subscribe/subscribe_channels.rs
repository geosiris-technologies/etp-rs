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

use crate::energistics::etp::v12::datatypes::channel_data::channel_subscribe_info::ChannelSubscribeInfo;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct SubscribeChannels {
    #[serde(rename = "channels")]
    pub channels: HashMap<String, ChannelSubscribeInfo>,
}

fn subscribechannels_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for SubscribeChannels {
    fn avro_schema(&self) -> Option<Schema> {
        subscribechannels_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for SubscribeChannels {}

impl AvroDeserializable for SubscribeChannels {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<SubscribeChannels> {
        let record =
            from_avro_datum(&subscribechannels_avro_schema().unwrap(), input, None).unwrap();
        from_value::<SubscribeChannels>(&record)
    }
}

impl ETPMetadata for SubscribeChannels {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        3
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

impl SubscribeChannels {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_SubscribeChannels(self.clone())
    }
}

impl Default for SubscribeChannels {
    /* Protocol 21, MessageType : 3 */
    fn default() -> SubscribeChannels {
        SubscribeChannels {
            channels: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "SubscribeChannels",
    "protocol": "21",
    "messageType": "3",
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
                    "name": "ChannelSubscribeInfo",
                    "fields": [
                        {
                            "name": "channelId",
                            "type": "long"
                        },
                        {
                            "name": "startIndex",
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
                        },
                        {
                            "name": "dataChanges",
                            "type": "boolean",
                            "default": true
                        },
                        {
                            "name": "requestLatestIndexCount",
                            "type": [
                                "null",
                                "int"
                            ]
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.ChannelSubscribeInfo",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.IndexValue"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.SubscribeChannels",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.ChannelSubscribeInfo"
    ]
}"#;
