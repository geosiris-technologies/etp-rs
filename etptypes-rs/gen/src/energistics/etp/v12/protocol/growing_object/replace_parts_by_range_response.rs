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

use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;
#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct ReplacePartsByRangeResponse {}

fn replacepartsbyrangeresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ReplacePartsByRangeResponse {
    fn avro_schema(&self) -> Option<Schema> {
        replacepartsbyrangeresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ReplacePartsByRangeResponse {}

impl AvroDeserializable for ReplacePartsByRangeResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ReplacePartsByRangeResponse> {
        let record = from_avro_datum(
            &replacepartsbyrangeresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<ReplacePartsByRangeResponse>(&record)
    }
}

impl ETPMetadata for ReplacePartsByRangeResponse {
    fn protocol(&self) -> i32 {
        6
    }
    fn message_type(&self) -> i32 {
        18
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl ReplacePartsByRangeResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_ReplacePartsByRangeResponse(self.clone())
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "ReplacePartsByRangeResponse",
    "protocol": "6",
    "messageType": "18",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.ReplacePartsByRangeResponse",
    "depends": []
}"#;
