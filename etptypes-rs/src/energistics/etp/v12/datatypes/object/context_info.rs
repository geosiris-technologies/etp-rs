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

use crate::energistics::etp::v12::datatypes::object::relationship_kind::RelationshipKind;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct ContextInfo {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "depth")]
    pub depth: i32,

    #[serde(rename = "dataObjectTypes")]
    #[derivative(Default(value = "Vec::new()"))]
    pub data_object_types: Vec<String>,

    #[serde(rename = "navigableEdges")]
    pub navigable_edges: RelationshipKind,

    #[serde(rename = "includeSecondaryTargets")]
    #[derivative(Default(value = "false"))]
    pub include_secondary_targets: bool,

    #[serde(rename = "includeSecondarySources")]
    #[derivative(Default(value = "false"))]
    pub include_secondary_sources: bool,
}

fn contextinfo_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ContextInfo {
    fn avro_schema(&self) -> Option<Schema> {
        contextinfo_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ContextInfo {}

impl AvroDeserializable for ContextInfo {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ContextInfo> {
        let record = from_avro_datum(&contextinfo_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ContextInfo>(&record)
    }
}

impl ContextInfo {
    /* Protocol , MessageType :  */
    pub fn default_with_params(
        uri: String,
        depth: i32,
        navigable_edges: RelationshipKind,
    ) -> ContextInfo {
        ContextInfo {
            uri,
            depth,
            data_object_types: vec![],
            navigable_edges,
            include_secondary_targets: false,
            include_secondary_sources: false,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
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
}"#;
