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
pub struct PutDataArraysResponse {
    #[serde(rename = "success")]
    pub success: HashMap<String, String>,
}

fn putdataarraysresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutDataArraysResponse {
    fn avro_schema(&self) -> Option<Schema> {
        putdataarraysresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutDataArraysResponse {}

impl AvroDeserializable for PutDataArraysResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutDataArraysResponse> {
        let record =
            from_avro_datum(&putdataarraysresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PutDataArraysResponse>(&record)
    }
}

impl ETPMetadata for PutDataArraysResponse {
    fn protocol(&self) -> i32 {
        9
    }
    fn message_type(&self) -> i32 {
        10
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

impl PutDataArraysResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::DataArray_PutDataArraysResponse(self.clone())
    }
}

impl Default for PutDataArraysResponse {
    /* Protocol 9, MessageType : 10 */
    fn default() -> PutDataArraysResponse {
        PutDataArraysResponse {
            success: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.DataArray",
    "name": "PutDataArraysResponse",
    "protocol": "9",
    "messageType": "10",
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
    "fullName": "Energistics.Etp.v12.Protocol.DataArray.PutDataArraysResponse",
    "depends": []
}"#;
