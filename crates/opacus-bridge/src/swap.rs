//! Swap protocol state machine

use crate::adaptor::SwapSecret;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SwapState {
    Initialized,
    OpacusLocked,
    MoneroEscrowed,
    SignaturesExchanged,
    Completed,
    Refunded,
    Failed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SwapId(pub [u8; 32]);

impl SwapId {
    pub fn new(initiator: &[u8], hash_lock: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"opacus_swap_id");
        hasher.update(initiator);
        hasher.update(hash_lock);
        Self(hasher.finalize().into())
    }
}

pub struct SwapEngine {
    sessions: HashMap<SwapId, SwapState>,
}

impl SwapEngine {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn initiate(&mut self, secret: &SwapSecret) -> SwapId {
        let id = SwapId::new(b"initiator", &secret.hash());
        self.sessions.insert(id.clone(), SwapState::Initialized);
        id
    }

    pub fn get_state(&self, id: &SwapId) -> Option<&SwapState> {
        self.sessions.get(id)
    }
}

impl Default for SwapEngine {
    fn default() -> Self {
        Self::new()
    }
}
