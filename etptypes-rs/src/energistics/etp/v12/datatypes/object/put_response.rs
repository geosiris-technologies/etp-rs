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
pub struct PutResponse {
    #[serde(rename = "createdContainedObjectUris")]
    #[derivative(Default(value = "Vec::new()"))]
    pub created_contained_object_uris: Vec<String>,

    #[serde(rename = "deletedContainedObjectUris")]
    #[derivative(Default(value = "Vec::new()"))]
    pub deleted_contained_object_uris: Vec<String>,

    #[serde(rename = "joinedContainedObjectUris")]
    #[derivative(Default(value = "Vec::new()"))]
    pub joined_contained_object_uris: Vec<String>,

    #[serde(rename = "unjoinedContainedObjectUris")]
    #[derivative(Default(value = "Vec::new()"))]
    pub unjoined_contained_object_uris: Vec<String>,
}

fn putresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutResponse {
    fn avro_schema(&self) -> Option<Schema> {
        putresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutResponse {}

impl AvroDeserializable for PutResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutResponse> {
        let record = from_avro_datum(&putresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PutResponse>(&record)
    }
}

impl Default for PutResponse {
    /* Protocol , MessageType :  */
    fn default() -> PutResponse {
        PutResponse {
            created_contained_object_uris: vec![],
            deleted_contained_object_uris: vec![],
            joined_contained_object_uris: vec![],
            unjoined_contained_object_uris: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.Object",
    "name": "PutResponse",
    "fields": [
        {
            "name": "createdContainedObjectUris",
            "type": {
                "type": "array",
                "items": "string"
            },
            "default": []
        },
        {
            "name": "deletedContainedObjectUris",
            "type": {
                "type": "array",
                "items": "string"
            },
            "default": []
        },
        {
            "name": "joinedContainedObjectUris",
            "type": {
                "type": "array",
                "items": "string"
            },
            "default": []
        },
        {
            "name": "unjoinedContainedObjectUris",
            "type": {
                "type": "array",
                "items": "string"
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Object.PutResponse",
    "depends": []
}"#;
