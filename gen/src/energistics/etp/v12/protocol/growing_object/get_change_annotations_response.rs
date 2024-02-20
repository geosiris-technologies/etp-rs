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

use crate::energistics::etp::v12::datatypes::object::change_response_info::ChangeResponseInfo;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetChangeAnnotationsResponse {
    #[serde(rename = "changes")]
    pub changes: HashMap<String, ChangeResponseInfo>,
}

fn getchangeannotationsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetChangeAnnotationsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        getchangeannotationsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetChangeAnnotationsResponse {}

impl AvroDeserializable for GetChangeAnnotationsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetChangeAnnotationsResponse> {
        let record = from_avro_datum(
            &getchangeannotationsresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<GetChangeAnnotationsResponse>(&record)
    }
}

impl ETPMetadata for GetChangeAnnotationsResponse {
    fn protocol(&self) -> i32 {
        6
    }
    fn message_type(&self) -> i32 {
        20
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

impl GetChangeAnnotationsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_GetChangeAnnotationsResponse(self.clone())
    }
}

impl Default for GetChangeAnnotationsResponse {
    /* Protocol 6, MessageType : 20 */
    fn default() -> GetChangeAnnotationsResponse {
        GetChangeAnnotationsResponse {
            changes: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "GetChangeAnnotationsResponse",
    "protocol": "6",
    "messageType": "20",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "changes",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "ChangeResponseInfo",
                    "fields": [
                        {
                            "name": "responseTimestamp",
                            "type": "long"
                        },
                        {
                            "name": "changes",
                            "type": {
                                "type": "map",
                                "values": {
                                    "type": "array",
                                    "items": {
                                        "type": "record",
                                        "namespace": "Energistics.Etp.v12.Datatypes.Object",
                                        "name": "ChangeAnnotation",
                                        "fields": [
                                            {
                                                "name": "changeTime",
                                                "type": "long"
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
                                            }
                                        ],
                                        "fullName": "Energistics.Etp.v12.Datatypes.Object.ChangeAnnotation",
                                        "depends": [
                                            "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
                                        ]
                                    }
                                }
                            }
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.ChangeResponseInfo",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.Object.ChangeAnnotation"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.GetChangeAnnotationsResponse",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.ChangeResponseInfo"
    ]
}"#;
