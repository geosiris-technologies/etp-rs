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
pub struct WMLS_GetVersionResponse {
    #[serde(rename = "Result")]
    pub result: String,
}

fn wmls_getversionresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for WMLS_GetVersionResponse {
    fn avro_schema(&self) -> Option<Schema> {
        wmls_getversionresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for WMLS_GetVersionResponse {}

impl AvroDeserializable for WMLS_GetVersionResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<WMLS_GetVersionResponse> {
        let record =
            from_avro_datum(&wmls_getversionresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<WMLS_GetVersionResponse>(&record)
    }
}

impl ETPMetadata for WMLS_GetVersionResponse {
    fn protocol(&self) -> i32 {
        2100
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
        false
    }
}

impl WMLS_GetVersionResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::WitsmlSoap_WMLS_GetVersionResponse(self.clone())
    }
}

impl Default for WMLS_GetVersionResponse {
    /* Protocol 2100, MessageType : 12 */
    fn default() -> WMLS_GetVersionResponse {
        WMLS_GetVersionResponse {
            result: "".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap",
    "name": "WMLS_GetVersionResponse",
    "protocol": "2100",
    "messageType": "12",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "Result",
            "type": "string"
        }
    ],
    "fullName": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap.WMLS_GetVersionResponse",
    "depends": []
}"#;
