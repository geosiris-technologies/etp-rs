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

use crate::energistics::etp::v12::datatypes::object::index_interval::IndexInterval;
use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetFrame {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "includeAllChannelSecondaryIndexes")]
    #[derivative(Default(value = "false"))]
    pub include_all_channel_secondary_indexes: bool,

    #[serde(rename = "requestedInterval")]
    pub requested_interval: IndexInterval,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,

    #[serde(rename = "requestedSecondaryIntervals")]
    #[derivative(Default(value = "Vec::new()"))]
    pub requested_secondary_intervals: Vec<IndexInterval>,
}

fn getframe_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetFrame {
    fn avro_schema(&self) -> Option<Schema> {
        getframe_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetFrame {}

impl AvroDeserializable for GetFrame {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetFrame> {
        let record = from_avro_datum(&getframe_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetFrame>(&record)
    }
}

impl ETPMetadata for GetFrame {
    fn protocol(&self) -> i32 {
        2
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

impl GetFrame {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelDataFrame_GetFrame(self.clone())
    }
}

impl GetFrame {
    /* Protocol 2, MessageType : 3 */
    pub fn default_with_params(uri: String, requested_interval: IndexInterval) -> GetFrame {
        GetFrame {
            uri,
            include_all_channel_secondary_indexes: false,
            requested_interval,
            request_uuid: random_uuid(),
            requested_secondary_intervals: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelDataFrame",
    "name": "GetFrame",
    "protocol": "2",
    "messageType": "3",
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
        },
        {
            "name": "requestedInterval",
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
            "name": "requestedSecondaryIntervals",
            "type": {
                "type": "array",
                "items": "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelDataFrame.GetFrame",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.IndexInterval",
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
