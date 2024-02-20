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
pub struct ArrayOfDouble {
    #[serde(rename = "values")]
    pub values: Vec<f64>,
}

fn arrayofdouble_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ArrayOfDouble {
    fn avro_schema(&self) -> Option<Schema> {
        arrayofdouble_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ArrayOfDouble {}

impl AvroDeserializable for ArrayOfDouble {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ArrayOfDouble> {
        let record = from_avro_datum(&arrayofdouble_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ArrayOfDouble>(&record)
    }
}

impl Default for ArrayOfDouble {
    /* Protocol , MessageType :  */
    fn default() -> ArrayOfDouble {
        ArrayOfDouble { values: vec![] }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes",
    "name": "ArrayOfDouble",
    "fields": [
        {
            "name": "values",
            "type": {
                "type": "array",
                "items": "double"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfDouble",
    "depends": []
}"#;
