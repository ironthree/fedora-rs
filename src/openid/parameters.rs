use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// This struct represents an OpenID endpoint's response after a successful authentication request.
#[derive(Debug, Deserialize)]
pub struct OpenIDResponse {
    pub success: bool,
    pub response: OpenIDParameters,
}

/// This struct contains the concrete OpenID parameters. They are currently unused, except for the
/// `openid.return_to` parameter.
#[allow(missing_docs)]
#[derive(Debug, Deserialize, Serialize)]
pub struct OpenIDParameters {
    #[serde(rename = "openid.assoc_handle")]
    pub assoc_handle: String,
    #[serde(rename = "openid.cla.signed_cla")]
    pub cla_signed_cla: String,
    #[serde(rename = "openid.claimed_id")]
    pub claimed_id: String,
    #[serde(rename = "openid.identity")]
    pub identity: String,
    #[serde(rename = "openid.lp.is_member")]
    pub lp_is_member: String,
    #[serde(rename = "openid.mode")]
    pub mode: String,
    #[serde(rename = "openid.ns")]
    pub ns: String,
    #[serde(rename = "openid.ns.cla")]
    pub ns_cla: String,
    #[serde(rename = "openid.ns.lp")]
    pub ns_lp: String,
    #[serde(rename = "openid.ns.sreg")]
    pub ns_sreg: String,
    #[serde(rename = "openid.op_endpoint")]
    pub op_endpoint: String,
    #[serde(rename = "openid.response_nonce")]
    pub response_nonce: String,
    /// This parameter is used to determine which URL to return to for completing a successful
    /// authentication flow.
    #[serde(rename = "openid.return_to")]
    pub return_to: String,
    #[serde(rename = "openid.sig")]
    pub sig: String,
    #[serde(rename = "openid.signed")]
    pub signed: String,
    #[serde(rename = "openid.sreg.email")]
    pub sreg_email: String,
    #[serde(rename = "openid.sreg.nickname")]
    pub sreg_nickname: String,

    /// This catch-all map contains all attributes that are not captured by the known parameters.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
