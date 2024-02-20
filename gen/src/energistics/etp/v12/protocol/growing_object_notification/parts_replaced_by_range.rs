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
use crate::energistics::etp::v12::datatypes::object::object_part::ObjectPart;
use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PartsReplacedByRange {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,

    #[serde(rename = "changeTime")]
    pub change_time: i64,

    #[serde(rename = "deletedInterval")]
    pub deleted_interval: IndexInterval,

    #[serde(rename = "includeOverlappingIntervals")]
    pub include_overlapping_intervals: bool,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("")"#))]
    pub format: String,

    #[serde(rename = "parts")]
    pub parts: Vec<ObjectPart>,
}

fn partsreplacedbyrange_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PartsReplacedByRange {
    fn avro_schema(&self) -> Option<Schema> {
        partsreplacedbyrange_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PartsReplacedByRange {}

impl AvroDeserializable for PartsReplacedByRange {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PartsReplacedByRange> {
        let record =
            from_avro_datum(&partsreplacedbyrange_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PartsReplacedByRange>(&record)
    }
}

impl ETPMetadata for PartsReplacedByRange {
    fn protocol(&self) -> i32 {
        7
    }
    fn message_type(&self) -> i32 {
        6
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

impl PartsReplacedByRange {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObjectNotification_PartsReplacedByRange(self.clone())
    }
}

impl PartsReplacedByRange {
    /* Protocol 7, MessageType : 6 */
    pub fn default_with_params(
        uri: String,
        deleted_interval: IndexInterval,
    ) -> PartsReplacedByRange {
        PartsReplacedByRange {
            uri,
            request_uuid: random_uuid(),
            change_time: time_to_etp(SystemTime::now()),
            deleted_interval,
            include_overlapping_intervals: true,
            format: "".to_string(),
            parts: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObjectNotification",
    "name": "PartsReplacedByRange",
    "protocol": "7",
    "messageType": "6",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "uri",
            "type": "string"
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
            "name": "changeTime",
            "type": "long"
        },
        {
            "name": "deletedInterval",
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
            "name": "includeOverlappingIntervals",
            "type": "boolean"
        },
        {
            "name": "format",
            "type": "string",
            "default": ""
        },
        {
            "name": "parts",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "ObjectPart",
                    "fields": [
                        {
                            "name": "uid",
                            "type": "string"
                        },
                        {
                            "name": "data",
                            "type": "bytes"
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.ObjectPart",
                    "depends": []
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObjectNotification.PartsReplacedByRange",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid",
        "Energistics.Etp.v12.Datatypes.Object.IndexInterval",
        "Energistics.Etp.v12.Datatypes.Object.ObjectPart"
    ]
}"#;
