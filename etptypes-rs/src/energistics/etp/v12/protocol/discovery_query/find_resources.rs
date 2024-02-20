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

use crate::energistics::etp::v12::datatypes::object::active_status_kind::ActiveStatusKind;
use crate::energistics::etp::v12::datatypes::object::context_info::ContextInfo;
use crate::energistics::etp::v12::datatypes::object::context_scope_kind::ContextScopeKind;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct FindResources {
    #[serde(rename = "context")]
    pub context: ContextInfo,

    #[serde(rename = "scope")]
    pub scope: ContextScopeKind,

    #[serde(rename = "storeLastWriteFilter")]
    pub store_last_write_filter: Option<i64>,

    #[serde(rename = "activeStatusFilter")]
    pub active_status_filter: Option<ActiveStatusKind>,
}

fn findresources_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for FindResources {
    fn avro_schema(&self) -> Option<Schema> {
        findresources_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for FindResources {}

impl AvroDeserializable for FindResources {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<FindResources> {
        let record = from_avro_datum(&findresources_avro_schema().unwrap(), input, None).unwrap();
        from_value::<FindResources>(&record)
    }
}

impl ETPMetadata for FindResources {
    fn protocol(&self) -> i32 {
        13
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

impl FindResources {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::DiscoveryQuery_FindResources(self.clone())
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.DiscoveryQuery",
    "name": "FindResources",
    "protocol": "13",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "context",
            "type": {
                "type": "record",
                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                "name": "ContextInfo",
                "fields": [
                    {
                        "name": "uri",
                        "type": "string"
                    },
                    {
                        "name": "depth",
                        "type": "int"
                    },
                    {
                        "name": "dataObjectTypes",
                        "type": {
                            "type": "array",
                            "items": "string"
                        },
                        "default": []
                    },
                    {
                        "name": "navigableEdges",
                        "type": {
                            "type": "enum",
                            "namespace": "Energistics.Etp.v12.Datatypes.Object",
                            "name": "RelationshipKind",
                            "symbols": [
                                "Primary",
                                "Secondary",
                                "Both"
                            ],
                            "fullName": "Energistics.Etp.v12.Datatypes.Object.RelationshipKind",
                            "depends": []
                        }
                    },
                    {
                        "name": "includeSecondaryTargets",
                        "type": "boolean",
                        "default": false
                    },
                    {
                        "name": "includeSecondarySources",
                        "type": "boolean",
                        "default": false
                    }
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.Object.ContextInfo",
                "depends": [
                    "Energistics.Etp.v12.Datatypes.Object.RelationshipKind"
                ]
            }
        },
        {
            "name": "scope",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                "name": "ContextScopeKind",
                "symbols": [
                    "self",
                    "sources",
                    "targets",
                    "sourcesOrSelf",
                    "targetsOrSelf"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind",
                "depends": []
            }
        },
        {
            "name": "storeLastWriteFilter",
            "type": [
                "null",
                "long"
            ]
        },
        {
            "name": "activeStatusFilter",
            "type": [
                "null",
                {
                    "type": "enum",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "ActiveStatusKind",
                    "symbols": [
                        "Active",
                        "Inactive"
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.ActiveStatusKind",
                    "depends": []
                }
            ]
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.DiscoveryQuery.FindResources",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.ContextInfo",
        "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind",
        "Energistics.Etp.v12.Datatypes.Object.ActiveStatusKind"
    ]
}"#;
