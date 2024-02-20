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
pub struct SupportedType {
    #[serde(rename = "dataObjectType")]
    pub data_object_type: String,

    #[serde(rename = "objectCount")]
    pub object_count: Option<i32>,

    #[serde(rename = "relationshipKind")]
    pub relationship_kind: RelationshipKind,
}

fn supportedtype_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for SupportedType {
    fn avro_schema(&self) -> Option<Schema> {
        supportedtype_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for SupportedType {}

impl AvroDeserializable for SupportedType {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<SupportedType> {
        let record = from_avro_datum(&supportedtype_avro_schema().unwrap(), input, None).unwrap();
        from_value::<SupportedType>(&record)
    }
}

impl SupportedType {
    /* Protocol , MessageType :  */
    pub fn default_with_params(
        object_count: Option<i32>,
        relationship_kind: RelationshipKind,
    ) -> SupportedType {
        SupportedType {
            data_object_type: "".to_string(),
            object_count,
            relationship_kind,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.Object",
    "name": "SupportedType",
    "fields": [
        {
            "name": "dataObjectType",
            "type": "string"
        },
        {
            "name": "objectCount",
            "type": [
                "null",
                "int"
            ]
        },
        {
            "name": "relationshipKind",
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
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Object.SupportedType",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.RelationshipKind"
    ]
}"#;
