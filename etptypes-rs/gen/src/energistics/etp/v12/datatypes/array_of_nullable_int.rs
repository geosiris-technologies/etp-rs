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
use std::io::Read; // ['i32']
#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct ArrayOfNullableInt {
    #[serde(rename = "values")]
    pub values: Vec<Option<i32>>,
}

fn arrayofnullableint_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ArrayOfNullableInt {
    fn avro_schema(&self) -> Option<Schema> {
        arrayofnullableint_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ArrayOfNullableInt {}

impl AvroDeserializable for ArrayOfNullableInt {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ArrayOfNullableInt> {
        let record =
            from_avro_datum(&arrayofnullableint_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ArrayOfNullableInt>(&record)
    }
}

impl Default for ArrayOfNullableInt {
    /* Protocol , MessageType :  */
    fn default() -> ArrayOfNullableInt {
        ArrayOfNullableInt { values: vec![] }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes",
    "name": "ArrayOfNullableInt",
    "fields": [
        {
            "name": "values",
            "type": {
                "type": "array",
                "items": [
                    "null",
                    "int"
                ]
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfNullableInt",
    "depends": []
}"#;
