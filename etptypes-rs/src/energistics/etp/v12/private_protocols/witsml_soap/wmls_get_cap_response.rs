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
pub struct WMLS_GetCapResponse {
    #[serde(rename = "Result")]
    pub result: i32,

    #[serde(rename = "CapabilitiesOut")]
    pub capabilities_out: String,

    #[serde(rename = "SuppMsgOut")]
    pub supp_msg_out: String,
}

fn wmls_getcapresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for WMLS_GetCapResponse {
    fn avro_schema(&self) -> Option<Schema> {
        wmls_getcapresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for WMLS_GetCapResponse {}

impl AvroDeserializable for WMLS_GetCapResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<WMLS_GetCapResponse> {
        let record =
            from_avro_datum(&wmls_getcapresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<WMLS_GetCapResponse>(&record)
    }
}

impl ETPMetadata for WMLS_GetCapResponse {
    fn protocol(&self) -> i32 {
        2100
    }
    fn message_type(&self) -> i32 {
        8
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

impl WMLS_GetCapResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::WitsmlSoap_WMLS_GetCapResponse(self.clone())
    }
}

impl WMLS_GetCapResponse {
    /* Protocol 2100, MessageType : 8 */
    pub fn default_with_params(result: i32) -> WMLS_GetCapResponse {
        WMLS_GetCapResponse {
            result,
            capabilities_out: "".to_string(),
            supp_msg_out: "".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap",
    "name": "WMLS_GetCapResponse",
    "protocol": "2100",
    "messageType": "8",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "Result",
            "type": "int"
        },
        {
            "name": "CapabilitiesOut",
            "type": "string"
        },
        {
            "name": "SuppMsgOut",
            "type": "string"
        }
    ],
    "fullName": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap.WMLS_GetCapResponse",
    "depends": []
}"#;
