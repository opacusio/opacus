//! monero-wallet-rpc / monerod JSON-RPC client (request builders + response
//! parsers, transport-agnostic). Plug any HTTP transport into [`Transport`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum XmrRpcError {
    Transport(String),
    Rpc(String),
    BadResponse(String),
}

impl std::fmt::Display for XmrRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XmrRpcError::Transport(m) => write!(f, "transport: {m}"),
            XmrRpcError::Rpc(m) => write!(f, "monero rpc: {m}"),
            XmrRpcError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

impl std::error::Error for XmrRpcError {}

/// Blocking transport used for wallet-rpc / daemon calls.
pub trait Transport {
    fn post(&self, url: &str, body: &Value) -> Result<Value, XmrRpcError>;
    /// Plain GET for monerod REST endpoints (e.g. `/get_info`).
    fn get(&self, url: &str) -> Result<Value, XmrRpcError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    fn post(&self, url: &str, body: &Value) -> Result<Value, XmrRpcError> {
        (**self).post(url, body)
    }
    fn get(&self, url: &str) -> Result<Value, XmrRpcError> {
        (**self).get(url)
    }
}

/// monero-wallet-rpc client.
pub struct WalletRpc<T: Transport> {
    pub url: String,
    pub transport: T,
}

/// monerod client.
pub struct DaemonRpc<T: Transport> {
    pub url: String,
    pub transport: T,
}

// ---------------------------------------------------------------------------
// Requests / responses (only the fields the bridge needs)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct TransferRequest {
    /// Destination address (single-output transfer).
    pub address: String,
    /// Amount in piconero (1 XMR = 1e12).
    pub amount: u64,
    /// For swap timelocks: min block height before the output spends.
    pub unlock_time: u64,
    /// Swap hashlock as hex payment_id.
    pub payment_id: String,
    pub account_index: u32,
    pub priority: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TransferResult {
    pub tx_hash: String,
    #[serde(default)]
    pub fee: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DaemonInfo {
    pub height: u64,
    #[serde(default)]
    pub synchronized: bool,
    #[serde(default)]
    pub target_height: u64,
}

/// `get_transactions` entry (only the fields the bridge needs). `as_hex` is
/// the full unpruned tx blob for nodes that serve prunable data.
#[derive(Clone, Debug, Deserialize)]
pub struct DaemonTx {
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub as_hex: String,
    #[serde(default)]
    pub as_json: Option<String>,
    #[serde(default)]
    pub pruned: bool,
    #[serde(default)]
    pub in_pool: bool,
    #[serde(default)]
    pub block_height: u64,
}

/// `get_outs` entry: one chain output by absolute index (ring member data).
#[derive(Clone, Debug, Deserialize)]
pub struct DaemonOut {
    #[serde(default)]
    pub index: u64,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub mask: String,
    #[serde(default)]
    pub unlocked: bool,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub txid: String,
}

// ---------------------------------------------------------------------------
// Wallet RPC
// ---------------------------------------------------------------------------

impl<T: Transport> WalletRpc<T> {
    pub fn new(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
        }
    }

    fn jsonrpc(&self, method: &str, params: Value) -> Result<Value, XmrRpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });
        let resp = self.transport.post(&self.url, &body)?;
        if let Some(err) = resp.get("error") {
            return Err(XmrRpcError::Rpc(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| XmrRpcError::BadResponse("missing result".into()))
    }

    /// Lock XMR for the swap: amount + unlock_time + payment_id (hashlock).
    pub fn transfer(&self, req: &TransferRequest) -> Result<TransferResult, XmrRpcError> {
        let params = json!({
            "destinations": [{"amount": req.amount, "address": req.address}],
            "account_index": req.account_index,
            "priority": req.priority,
            "unlock_time": req.unlock_time,
            "payment_id": req.payment_id,
        });
        let res = self.jsonrpc("transfer", params)?;
        let tx_hash = res
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| XmrRpcError::BadResponse("missing tx_hash".into()))?
            .to_string();
        let fee = res.get("fee").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(TransferResult { tx_hash, fee })
    }

    /// Incoming transfers with a given payment id (swap lock detection).
    pub fn transfers_by_payment_id(&self, payment_id: &str) -> Result<Vec<String>, XmrRpcError> {
        let res = self.jsonrpc(
            "get_transfers",
            json!({"in": true, "out": false, "pending": false, "failed": false}),
        )?;
        let mut hashes = Vec::new();
        if let Some(list) = res.get("in").and_then(|v| v.as_array()) {
            for tx in list {
                let pid = tx.get("payment_id").and_then(|v| v.as_str()).unwrap_or("");
                if pid == payment_id {
                    if let Some(h) = tx.get("tx_hash").and_then(|v| v.as_str()) {
                        hashes.push(h.to_string());
                    }
                }
            }
        }
        Ok(hashes)
    }

    /// Primary address of the opened wallet (for receiving GHOST proceeds
    /// side-effects, bookkeeping, etc).
    pub fn get_address(&self, account_index: u32) -> Result<String, XmrRpcError> {
        let res = self.jsonrpc("get_address", json!({"account_index": account_index}))?;
        res.get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| XmrRpcError::BadResponse("missing address".into()))
    }

    /// Unlocked (spendable) balance in piconero.
    pub fn unlocked_balance(&self, account_index: u32) -> Result<u64, XmrRpcError> {
        let res = self.jsonrpc("get_balance", json!({"account_index": account_index}))?;
        res.get("unlocked_balance")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| XmrRpcError::BadResponse("missing unlocked_balance".into()))
    }
}

// ---------------------------------------------------------------------------
// Daemon RPC
// ---------------------------------------------------------------------------

impl<T: Transport> DaemonRpc<T> {
    pub fn new(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
        }
    }

    fn jsonrpc(&self, method: &str, params: Value) -> Result<Value, XmrRpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });
        let resp = self.transport.post(&self.url, &body)?;
        if let Some(err) = resp.get("error") {
            return Err(XmrRpcError::Rpc(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| XmrRpcError::BadResponse("missing result".into()))
    }

    /// GET /get_info (monerod REST endpoint).
    pub fn get_info(&self) -> Result<DaemonInfo, XmrRpcError> {
        let url = format!("{}/get_info", self.url.trim_end_matches('/'));
        let v = self.transport.get(&url)?;
        serde_json::from_value(v).map_err(|e| XmrRpcError::BadResponse(e.to_string()))
    }

    /// get_transactions: full (unpruned) tx blobs by hash — the CLSAG
    /// fixture source (WG-CLSAG section 6.1).
    pub fn get_transactions(&self, txs_hashes: &[String]) -> Result<Vec<DaemonTx>, XmrRpcError> {
        let res = self.jsonrpc(
            "get_transactions",
            json!({"txs_hashes": txs_hashes, "decode_as_json": true, "prune": false}),
        )?;
        let missed = res
            .get("missed_tx")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if missed {
            return Err(XmrRpcError::BadResponse(
                "missed_tx in get_transactions response".into(),
            ));
        }
        let txs = res
            .get("txs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        txs.iter()
            .map(|t| {
                serde_json::from_value(t.clone())
                    .map_err(|e| XmrRpcError::BadResponse(e.to_string()))
            })
            .collect()
    }

    /// get_outs: one-time keys (key) and amount commitments (mask) of chain
    /// outputs by absolute output index — the ring member source for CLSAG
    /// verification (WG-CLSAG section 3.2).
    pub fn get_outs(&self, indices: &[u64]) -> Result<Vec<DaemonOut>, XmrRpcError> {
        let outputs: Vec<Value> = indices.iter().map(|i| json!({"index": i})).collect();
        let res = self.jsonrpc("get_outs", json!({"outputs": outputs, "get_txid": true}))?;
        let outs = res
            .get("outs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        outs.iter()
            .map(|o| {
                serde_json::from_value(o.clone())
                    .map_err(|e| XmrRpcError::BadResponse(e.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        calls: RefCell<Vec<(String, Value)>>,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
            }
        }
        fn record(&self, url: &str, body: &Value) {
            self.calls
                .borrow_mut()
                .push((url.to_string(), body.clone()));
        }
    }

    impl Transport for FakeTransport {
        fn post(&self, url: &str, body: &Value) -> Result<Value, XmrRpcError> {
            self.record(url, body);
            let method = body["method"].as_str().unwrap_or("");
            if method == "transfer" {
                return Ok(json!({
                    "id": "0",
                    "result": {"tx_hash": "abc123", "fee": 12345}
                }));
            }
            if method == "get_balance" {
                return Ok(json!({"id": "0", "result": {"unlocked_balance": 9876}}));
            }
            if method == "get_address" {
                return Ok(json!({"id": "0", "result": {"address": "4At3X..."}}));
            }
            if method == "get_transactions" {
                let hashes = body["params"]["txs_hashes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let txs: Vec<Value> = hashes
                    .iter()
                    .map(|h| {
                        json!({
                            "tx_hash": h.as_str().unwrap_or(""),
                            "as_hex": "deadbeef",
                            "as_json": "{\"version\":2}",
                            "pruned": false,
                            "in_pool": false,
                            "block_height": 3_796_485u64
                        })
                    })
                    .collect();
                return Ok(json!({"id": "0", "result": {"txs": txs}}));
            }
            if method == "get_outs" {
                let outs: Vec<Value> = body["params"]["outputs"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|o| {
                        json!({
                            "index": o["index"],
                            "key": "5eab1a72b32b87904da7b17879632a3aad78a7b44c72c0ef76e059c51792232a",
                            "mask": "8c5a34f8e9f3ecb12c3b6dc07dca91e2f26dee8683afd0b3c74ff23e5c8d8a20",
                            "unlocked": true,
                            "height": 3_700_000u64,
                            "txid": "43bd6f459b84f14162143e28c83a0fd1d58cb8e4c328070fa79ca198a0c79a23"
                        })
                    })
                    .collect();
                return Ok(json!({"id": "0", "result": {"outs": outs, "status": "OK"}}));
            }
            Err(XmrRpcError::Rpc("unknown".into()))
        }

        fn get(&self, _url: &str) -> Result<Value, XmrRpcError> {
            Ok(json!({
                "height": 3_200_000,
                "synchronized": true,
                "target_height": 3_200_001
            }))
        }
    }

    #[test]
    fn transfer_request_shape_and_parse() {
        let t = FakeTransport::new();
        let rpc = WalletRpc::new("http://127.0.0.1:18083/json_rpc", &t);
        let req = TransferRequest {
            address: "4At3X...".into(),
            amount: 2_000_000_000_000,
            unlock_time: 3_200_100,
            payment_id: hex::encode([0x11u8; 32]),
            account_index: 0,
            priority: 0,
        };
        let res = rpc.transfer(&req).unwrap();
        assert_eq!(res.tx_hash, "abc123");
        assert_eq!(res.fee, 12345);

        let (_, body) = &t.calls.borrow()[0];
        assert_eq!(body["method"], "transfer");
        assert_eq!(body["params"]["unlock_time"], 3_200_100u64);
        assert_eq!(body["params"]["payment_id"], hex::encode([0x11u8; 32]));
        assert_eq!(
            body["params"]["destinations"][0]["amount"],
            2_000_000_000_000u64
        );
        assert_eq!(body["params"]["destinations"][0]["address"], "4At3X...");
    }

    #[test]
    fn balance_and_address() {
        let t = FakeTransport::new();
        let rpc = WalletRpc::new("http://127.0.0.1:18083/json_rpc", &t);
        assert_eq!(rpc.unlocked_balance(0).unwrap(), 9876);
        assert_eq!(rpc.get_address(0).unwrap(), "4At3X...");
    }

    #[test]
    fn daemon_info() {
        let t = FakeTransport::new();
        let d = DaemonRpc::new("http://127.0.0.1:18081", &t);
        let info = d.get_info().unwrap();
        assert_eq!(info.height, 3_200_000);
        assert!(info.synchronized);
    }

    #[test]
    fn get_transactions_roundtrip_and_shape() {
        let t = FakeTransport::new();
        let d = DaemonRpc::new("http://127.0.0.1:18081/json_rpc", &t);
        let hash = "43bd6f459b84f14162143e28c83a0fd1d58cb8e4c328070fa79ca198a0c79a23".to_string();
        let txs = d.get_transactions(std::slice::from_ref(&hash)).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].tx_hash, hash);
        assert_eq!(txs[0].as_hex, "deadbeef");
        assert!(!txs[0].pruned);
        assert_eq!(txs[0].block_height, 3_796_485);
        let (url, body) = &t.calls.borrow()[0];
        assert_eq!(url, "http://127.0.0.1:18081/json_rpc");
        assert_eq!(body["method"], "get_transactions");
        assert_eq!(body["params"]["prune"], false);
        assert_eq!(body["params"]["txs_hashes"][0], hash);
    }

    #[test]
    fn get_transactions_missed_tx_is_error() {
        struct MissedTransport;
        impl Transport for MissedTransport {
            fn post(&self, _: &str, _: &Value) -> Result<Value, XmrRpcError> {
                Ok(json!({"id": "0", "result": {"txs": [], "missed_tx": ["gone"]}}))
            }
            fn get(&self, _: &str) -> Result<Value, XmrRpcError> {
                Err(XmrRpcError::Transport("unused".into()))
            }
        }
        let d = DaemonRpc::new("http://x/json_rpc", MissedTransport);
        let err = d
            .get_transactions(&["aa".repeat(32)])
            .expect_err("missed_tx must fail closed");
        assert!(err.to_string().contains("missed_tx"));
    }

    #[test]
    fn get_outs_roundtrip_and_shape() {
        let t = FakeTransport::new();
        let d = DaemonRpc::new("http://127.0.0.1:18081/json_rpc", &t);
        let outs = d.get_outs(&[7, 9]).unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].index, 7);
        assert_eq!(outs[1].index, 9);
        assert!(outs[0].unlocked);
        assert_eq!(outs[0].key.len(), 64);
        assert_eq!(outs[0].mask.len(), 64);
        let (_, body) = &t.calls.borrow()[0];
        assert_eq!(body["method"], "get_outs");
        assert_eq!(body["params"]["outputs"][0]["index"], 7);
        assert_eq!(body["params"]["get_txid"], true);
    }

    #[test]
    fn transfer_error_propagates() {
        struct ErrTransport;
        impl Transport for ErrTransport {
            fn post(&self, _: &str, _: &Value) -> Result<Value, XmrRpcError> {
                Ok(json!({"id": "0", "error": {"code": -1, "message": "not enough money"}}))
            }
            fn get(&self, _: &str) -> Result<Value, XmrRpcError> {
                Err(XmrRpcError::Transport("unused".into()))
            }
        }
        let rpc = WalletRpc::new("http://x", ErrTransport);
        let err = rpc
            .transfer(&TransferRequest {
                address: "a".into(),
                amount: 1,
                unlock_time: 1,
                payment_id: "ff".into(),
                account_index: 0,
                priority: 0,
            })
            .unwrap_err();
        assert!(err.to_string().contains("not enough money"));
    }
}
