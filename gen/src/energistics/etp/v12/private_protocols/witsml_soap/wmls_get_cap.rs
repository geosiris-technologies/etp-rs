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
pub struct WMLS_GetCap {
    #[serde(rename = "OptionsIn")]
    pub options_in: String,
}

fn wmls_getcap_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for WMLS_GetCap {
    fn avro_schema(&self) -> Option<Schema> {
        wmls_getcap_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for WMLS_GetCap {}

impl AvroDeserializable for WMLS_GetCap {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<WMLS_GetCap> {
        let record = from_avro_datum(&wmls_getcap_avro_schema().unwrap(), input, None).unwrap();
        from_value::<WMLS_GetCap>(&record)
    }
}

impl ETPMetadata for WMLS_GetCap {
    fn protocol(&self) -> i32 {
        2100
    }
    fn message_type(&self) -> i32 {
        7
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Customer]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl WMLS_GetCap {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::WitsmlSoap_WMLS_GetCap(self.clone())
    }
}

impl Default for WMLS_GetCap {
    /* Protocol 2100, MessageType : 7 */
    fn default() -> WMLS_GetCap {
        WMLS_GetCap {
            options_in: "".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap",
    "name": "WMLS_GetCap",
    "protocol": "2100",
    "messageType": "7",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "OptionsIn",
            "type": "string"
        }
    ],
    "fullName": "Energistics.Etp.v12.PrivateProtocols.WitsmlSoap.WMLS_GetCap",
    "depends": []
}"#;
