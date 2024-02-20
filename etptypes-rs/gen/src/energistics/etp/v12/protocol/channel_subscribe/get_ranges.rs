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

use crate::energistics::etp::v12::datatypes::channel_data::channel_range_info::ChannelRangeInfo;
use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetRanges {
    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,

    #[serde(rename = "channelRanges")]
    pub channel_ranges: Vec<ChannelRangeInfo>,
}

fn getranges_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetRanges {
    fn avro_schema(&self) -> Option<Schema> {
        getranges_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetRanges {}

impl AvroDeserializable for GetRanges {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetRanges> {
        let record = from_avro_datum(&getranges_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetRanges>(&record)
    }
}

impl ETPMetadata for GetRanges {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        9
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

impl GetRanges {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_GetRanges(self.clone())
    }
}

impl Default for GetRanges {
    /* Protocol 21, MessageType : 9 */
    fn default() -> GetRanges {
        GetRanges {
            request_uuid: random_uuid(),
            channel_ranges: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "GetRanges",
    "protocol": "21",
    "messageType": "9",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "requestUuid",
            "type": {
                "type": "fixed",
                "namespace": "Energistics.Etp.v12.Datatypes",
                "name": "Uuid",
                "size": 16,
                "fullName": "Energistics.Etp.v12.Datatypes.Uuid",
                "depends": []
            }
        },
        {
            "name": "channelRanges",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                    "name": "ChannelRangeInfo",
                    "fields": [
                        {
                            "name": "channelIds",
                            "type": {
                                "type": "array",
                                "items": "long"
                            }
                        },
                        {
                            "name": "interval",
                            "type": {
                                "type": "record",
                                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                                "name": "IndexInterval",
                                "fields": [
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
                                        "name": "endIndex",
                                        "type": "Energistics.Etp.v12.Datatypes.IndexValue"
                                    },
                                    {
                                        "name": "uom",
                                        "type": "string"
                                    },
                                    {
                                        "name": "depthDatum",
                                        "type": "string",
                                        "default": ""
                                    }
                                ],
                                "fullName": "Energistics.Etp.v12.Datatypes.Object.IndexInterval",
                                "depends": [
                                    "Energistics.Etp.v12.Datatypes.IndexValue"
                                ]
                            }
                        },
                        {
                            "name": "secondaryIntervals",
                            "type": {
                                "type": "array",
                                "items": "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
                            },
                            "default": []
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.ChannelRangeInfo",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.GetRanges",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid",
        "Energistics.Etp.v12.Datatypes.ChannelData.ChannelRangeInfo"
    ]
}"#;
