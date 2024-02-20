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

use crate::energistics::etp::v12::datatypes::channel_data::channel_data_kind::ChannelDataKind;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct AttributeMetadataRecord {
    #[serde(rename = "attributeId")]
    pub attribute_id: i32,

    #[serde(rename = "attributeName")]
    pub attribute_name: String,

    #[serde(rename = "dataKind")]
    pub data_kind: ChannelDataKind,

    #[serde(rename = "uom")]
    pub uom: String,

    #[serde(rename = "depthDatum")]
    pub depth_datum: String,

    #[serde(rename = "attributePropertyKindUri")]
    pub attribute_property_kind_uri: String,

    #[serde(rename = "axisVectorLengths")]
    pub axis_vector_lengths: Vec<i32>,
}

fn attributemetadatarecord_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for AttributeMetadataRecord {
    fn avro_schema(&self) -> Option<Schema> {
        attributemetadatarecord_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for AttributeMetadataRecord {}

impl AvroDeserializable for AttributeMetadataRecord {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<AttributeMetadataRecord> {
        let record =
            from_avro_datum(&attributemetadatarecord_avro_schema().unwrap(), input, None).unwrap();
        from_value::<AttributeMetadataRecord>(&record)
    }
}

impl AttributeMetadataRecord {
    /* Protocol , MessageType :  */
    pub fn default_with_params(
        attribute_id: i32,
        data_kind: ChannelDataKind,
    ) -> AttributeMetadataRecord {
        AttributeMetadataRecord {
            attribute_id,
            attribute_name: "".to_string(),
            data_kind,
            uom: "".to_string(),
            depth_datum: "".to_string(),
            attribute_property_kind_uri: "".to_string(),
            axis_vector_lengths: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes",
    "name": "AttributeMetadataRecord",
    "fields": [
        {
            "name": "attributeId",
            "type": "int"
        },
        {
            "name": "attributeName",
            "type": "string"
        },
        {
            "name": "dataKind",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                "name": "ChannelDataKind",
                "symbols": [
                    "DateTime",
                    "ElapsedTime",
                    "MeasuredDepth",
                    "PassIndexedDepth",
                    "TrueVerticalDepth",
                    "typeBoolean",
                    "typeInt",
                    "typeLong",
                    "typeFloat",
                    "typeDouble",
                    "typeString",
                    "typeBytes"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.ChannelDataKind",
                "depends": []
            }
        },
        {
            "name": "uom",
            "type": "string"
        },
        {
            "name": "depthDatum",
            "type": "string"
        },
        {
            "name": "attributePropertyKindUri",
            "type": "string"
        },
        {
            "name": "axisVectorLengths",
            "type": {
                "type": "array",
                "items": "int"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.AttributeMetadataRecord",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.ChannelDataKind"
    ]
}"#;
