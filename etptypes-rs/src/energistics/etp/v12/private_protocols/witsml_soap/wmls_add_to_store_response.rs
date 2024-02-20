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
pub struct WMLS_AddToStoreResponse {
    #[serde(rename = "Result")]
    pub result: i32,

    #[serde(rename = "SuppMsgOut")]
    pub supp_msg_out: String,
}

fn wmls_addtostoreresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for WMLS_AddToStoreResponse {
    fn avro_schema(&self) -> Option<Schema> {
        wmls_addtostoreresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for WMLS_AddToStoreResponse {}

impl AvroDeserializable for WMLS_AddToStoreResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<WMLS_AddToStoreResponse> {
        let record =
            from_avro_datum(&wmls_addtostoreresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<WMLS_AddToStoreResponse>(&record)
    }
}

impl ETPMetadata for WMLS_AddToStoreResponse {
    fn protocol(&self) -> i32 {
        2100
    }
    fn message_type(&self) -> i32 {
        2
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

impl WMLS_AddToStoreResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::WitsmlSoap_WMLS_AddToStoreResponse(self.clone())
    }
}

impl WMLS_AddToStoreResponse {
    /* Protocol 2100, MessageType : 2 */
    pub fn default_with_params(result: i32) -> WMLS_AddToStoreResponse {
        WMLS_AddToStoreResponse {
            result,
            supp_msg_out: "".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap",
    "name": "WMLS_AddToStoreResponse",
    "protocol": "2100",
    "messageType": "2",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "Result",
            "type": "int"
        },
        {
            "name": "SuppMsgOut",
            "type": "string"
        }
    ],
    "fullName": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap.WMLS_AddToStoreResponse",
    "depends": []
}"#;
