#![allow(unused_imports)]
#![allow(non_camel_case_types)]
use bytes;
use derivative::Derivative;
use std::collections::HashMap;
use avro_rs::{Schema, Error};
use crate::helpers::EtpMessageBody;

use crate::energistics::etp::v12::datatypes::uuid::Uuid;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "camelCase")]
pub struct UnsubscribeNotifications{

	#[serde(rename = "requestUuid")]
    pub request_uuid:Uuid,

}

pub static AVRO_SCHEMA: &'static str = r#"{"type": "record", "namespace": "Energistics.Etp.v12.Protocol.StoreNotification", "name": "UnsubscribeNotifications", "protocol": "5", "messageType": "4", "senderRole": "customer", "protocolRoles": "store,customer", "multipartFlag": false, "fields": [{"name": "requestUuid", "type": {"type": "fixed", "namespace": "Energistics.Etp.v12.Datatypes", "name": "Uuid", "size": 16, "fullName": "Energistics.Etp.v12.Datatypes.Uuid", "depends": []}}], "fullName": "Energistics.Etp.v12.Protocol.StoreNotification.UnsubscribeNotifications", "depends": ["Energistics.Etp.v12.Datatypes.Uuid"]}"#;

impl EtpMessageBody for UnsubscribeNotifications{
    fn avro_schema() -> Option<Schema>{
        match Schema::parse_str(AVRO_SCHEMA) {
            Ok(result) => Some(result),
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }
    fn protocol(&self) ->i32{
        5
    }
    fn message_type(&self) ->i32{
        4
    }
    fn sender_role(&self) ->String{
        "customer".to_string()
    }
    fn protocol_roles(&self) ->String{
        "store,customer".to_string()
    }
    fn multipart_flag(&self) ->bool{
        false
    }
}

