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
pub struct MessageHeader {
    #[serde(rename = "protocol")]
    pub protocol: i32,

    #[serde(rename = "messageType")]
    pub message_type: i32,

    #[serde(rename = "correlationId")]
    pub correlation_id: i64,

    #[serde(rename = "messageId")]
    pub message_id: i64,

    #[serde(rename = "messageFlags")]
    pub message_flags: i32,
}

fn messageheader_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for MessageHeader {
    fn avro_schema(&self) -> Option<Schema> {
        messageheader_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for MessageHeader {}

impl AvroDeserializable for MessageHeader {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<MessageHeader> {
        let record = from_avro_datum(&messageheader_avro_schema().unwrap(), input, None).unwrap();
        from_value::<MessageHeader>(&record)
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes",
    "name": "MessageHeader",
    "fields": [
        {
            "name": "protocol",
            "type": "int"
        },
        {
            "name": "messageType",
            "type": "int"
        },
        {
            "name": "correlationId",
            "type": "long"
        },
        {
            "name": "messageId",
            "type": "long"
        },
        {
            "name": "messageFlags",
            "type": "int"
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.MessageHeader",
    "depends": []
}"#;
