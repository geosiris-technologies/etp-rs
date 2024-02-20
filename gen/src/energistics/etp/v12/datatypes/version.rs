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

use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;
#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct Version {
    #[serde(rename = "major")]
    #[derivative(Default(value = "0"))]
    pub major: i32,

    #[serde(rename = "minor")]
    #[derivative(Default(value = "0"))]
    pub minor: i32,

    #[serde(rename = "revision")]
    #[derivative(Default(value = "0"))]
    pub revision: i32,

    #[serde(rename = "patch")]
    #[derivative(Default(value = "0"))]
    pub patch: i32,
}

fn version_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for Version {
    fn avro_schema(&self) -> Option<Schema> {
        version_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for Version {}

impl AvroDeserializable for Version {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<Version> {
        let record = from_avro_datum(&version_avro_schema().unwrap(), input, None).unwrap();
        from_value::<Version>(&record)
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes",
    "name": "Version",
    "fields": [
        {
            "name": "major",
            "type": "int",
            "default": 0
        },
        {
            "name": "minor",
            "type": "int",
            "default": 0
        },
        {
            "name": "revision",
            "type": "int",
            "default": 0
        },
        {
            "name": "patch",
            "type": "int",
            "default": 0
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Version",
    "depends": []
}"#;
