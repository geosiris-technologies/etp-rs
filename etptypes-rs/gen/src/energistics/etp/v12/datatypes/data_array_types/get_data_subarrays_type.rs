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

use crate::energistics::etp::v12::datatypes::data_array_types::data_array_identifier::DataArrayIdentifier;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetDataSubarraysType {
    #[serde(rename = "uid")]
    pub uid: DataArrayIdentifier,

    #[serde(rename = "starts")]
    #[derivative(Default(value = "Vec::new()"))]
    pub starts: Vec<i64>,

    #[serde(rename = "counts")]
    #[derivative(Default(value = "Vec::new()"))]
    pub counts: Vec<i64>,
}

fn getdatasubarraystype_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetDataSubarraysType {
    fn avro_schema(&self) -> Option<Schema> {
        getdatasubarraystype_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetDataSubarraysType {}

impl AvroDeserializable for GetDataSubarraysType {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetDataSubarraysType> {
        let record =
            from_avro_datum(&getdatasubarraystype_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetDataSubarraysType>(&record)
    }
}

impl GetDataSubarraysType {
    /* Protocol , MessageType :  */
    pub fn default_with_params(uid: DataArrayIdentifier) -> GetDataSubarraysType {
        GetDataSubarraysType {
            uid,
            starts: vec![],
            counts: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
    "name": "GetDataSubarraysType",
    "fields": [
        {
            "name": "uid",
            "type": {
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
            }
        },
        {
            "name": "starts",
            "type": {
                "type": "array",
                "items": "long"
            },
            "default": []
        },
        {
            "name": "counts",
            "type": {
                "type": "array",
                "items": "long"
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.GetDataSubarraysType",
    "depends": [
        "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier"
    ]
}"#;
