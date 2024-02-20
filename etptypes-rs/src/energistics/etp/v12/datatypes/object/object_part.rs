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
pub struct ObjectPart {
    #[serde(rename = "uid")]
    pub uid: String,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "data")]
    pub data: Vec<u8>,
}

fn objectpart_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ObjectPart {
    fn avro_schema(&self) -> Option<Schema> {
        objectpart_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ObjectPart {}

impl AvroDeserializable for ObjectPart {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ObjectPart> {
        let record = from_avro_datum(&objectpart_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ObjectPart>(&record)
    }
}

impl ObjectPart {
    /* Protocol , MessageType :  */
    pub fn default_with_params(data: Vec<u8>) -> ObjectPart {
        ObjectPart {
            uid: "".to_string(),
            data,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
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
}"#;
