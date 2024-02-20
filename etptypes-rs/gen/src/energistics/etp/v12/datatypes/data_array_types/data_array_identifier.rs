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
pub struct DataArrayIdentifier {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "pathInResource")]
    pub path_in_resource: String,
}

fn dataarrayidentifier_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for DataArrayIdentifier {
    fn avro_schema(&self) -> Option<Schema> {
        dataarrayidentifier_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for DataArrayIdentifier {}

impl AvroDeserializable for DataArrayIdentifier {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<DataArrayIdentifier> {
        let record =
            from_avro_datum(&dataarrayidentifier_avro_schema().unwrap(), input, None).unwrap();
        from_value::<DataArrayIdentifier>(&record)
    }
}

impl DataArrayIdentifier {
    /* Protocol , MessageType :  */
    pub fn default_with_params(uri: String) -> DataArrayIdentifier {
        DataArrayIdentifier {
            uri,
            path_in_resource: "".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
    "name": "DataArrayIdentifier",
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "pathInResource",
            "type": "string"
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier",
    "depends": []
}"#;
