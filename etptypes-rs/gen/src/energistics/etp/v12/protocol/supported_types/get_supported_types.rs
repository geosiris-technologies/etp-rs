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

use crate::energistics::etp::v12::datatypes::object::context_scope_kind::ContextScopeKind;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetSupportedTypes {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "scope")]
    pub scope: ContextScopeKind,

    #[serde(rename = "returnEmptyTypes")]
    #[derivative(Default(value = "false"))]
    pub return_empty_types: bool,

    #[serde(rename = "countObjects")]
    #[derivative(Default(value = "false"))]
    pub count_objects: bool,
}

fn getsupportedtypes_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetSupportedTypes {
    fn avro_schema(&self) -> Option<Schema> {
        getsupportedtypes_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetSupportedTypes {}

impl AvroDeserializable for GetSupportedTypes {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetSupportedTypes> {
        let record =
            from_avro_datum(&getsupportedtypes_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetSupportedTypes>(&record)
    }
}

impl ETPMetadata for GetSupportedTypes {
    fn protocol(&self) -> i32 {
        25
    }
    fn message_type(&self) -> i32 {
        1
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

impl GetSupportedTypes {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::SupportedTypes_GetSupportedTypes(self.clone())
    }
}

impl GetSupportedTypes {
    /* Protocol 25, MessageType : 1 */
    pub fn default_with_params(uri: String, scope: ContextScopeKind) -> GetSupportedTypes {
        GetSupportedTypes {
            uri,
            scope,
            return_empty_types: false,
            count_objects: false,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.SupportedTypes",
    "name": "GetSupportedTypes",
    "protocol": "25",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "scope",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                "name": "ContextScopeKind",
                "symbols": [
                    "self",
                    "sources",
                    "targets",
                    "sourcesOrSelf",
                    "targetsOrSelf"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind",
                "depends": []
            }
        },
        {
            "name": "returnEmptyTypes",
            "type": "boolean",
            "default": false
        },
        {
            "name": "countObjects",
            "type": "boolean",
            "default": false
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.SupportedTypes.GetSupportedTypes",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind"
    ]
}"#;
