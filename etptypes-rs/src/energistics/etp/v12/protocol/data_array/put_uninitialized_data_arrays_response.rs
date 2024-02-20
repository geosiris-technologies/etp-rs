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
pub struct PutUninitializedDataArraysResponse {
    #[serde(rename = "success")]
    pub success: HashMap<String, String>,
}

fn putuninitializeddataarraysresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutUninitializedDataArraysResponse {
    fn avro_schema(&self) -> Option<Schema> {
        putuninitializeddataarraysresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutUninitializedDataArraysResponse {}

impl AvroDeserializable for PutUninitializedDataArraysResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutUninitializedDataArraysResponse> {
        let record = from_avro_datum(
            &putuninitializeddataarraysresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<PutUninitializedDataArraysResponse>(&record)
    }
}

impl ETPMetadata for PutUninitializedDataArraysResponse {
    fn protocol(&self) -> i32 {
        9
    }
    fn message_type(&self) -> i32 {
        12
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        true
    }
}

impl PutUninitializedDataArraysResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::DataArray_PutUninitializedDataArraysResponse(self.clone())
    }
}

impl Default for PutUninitializedDataArraysResponse {
    /* Protocol 9, MessageType : 12 */
    fn default() -> PutUninitializedDataArraysResponse {
        PutUninitializedDataArraysResponse {
            success: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.DataArray",
    "name": "PutUninitializedDataArraysResponse",
    "protocol": "9",
    "messageType": "12",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "success",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.DataArray.PutUninitializedDataArraysResponse",
    "depends": []
}"#;
