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

use crate::energistics::etp::v12::datatypes::object::context_info::ContextInfo;
use crate::energistics::etp::v12::datatypes::object::context_scope_kind::ContextScopeKind;
use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct SubscriptionInfo {
    #[serde(rename = "context")]
    pub context: ContextInfo,

    #[serde(rename = "scope")]
    pub scope: ContextScopeKind,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,

    #[serde(rename = "includeObjectData")]
    pub include_object_data: bool,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,
}

fn subscriptioninfo_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for SubscriptionInfo {
    fn avro_schema(&self) -> Option<Schema> {
        subscriptioninfo_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for SubscriptionInfo {}

impl AvroDeserializable for SubscriptionInfo {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<SubscriptionInfo> {
        let record =
            from_avro_datum(&subscriptioninfo_avro_schema().unwrap(), input, None).unwrap();
        from_value::<SubscriptionInfo>(&record)
    }
}

impl SubscriptionInfo {
    /* Protocol , MessageType :  */
    pub fn default_with_params(context: ContextInfo, scope: ContextScopeKind) -> SubscriptionInfo {
        SubscriptionInfo {
            context,
            scope,
            request_uuid: random_uuid(),
            include_object_data: true,
            format: "xml".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.Object",
    "name": "SubscriptionInfo",
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
            "name": "includeObjectData",
            "type": "boolean"
        },
        {
            "name": "format",
            "type": "string",
            "default": "xml"
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Object.SubscriptionInfo",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.ContextInfo",
        "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind",
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
