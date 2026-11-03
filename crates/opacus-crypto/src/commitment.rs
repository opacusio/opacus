//! Pedersen Commitments

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub point: CompressedRistretto,
}

fn generator_h() -> RistrettoPoint {
    let hash = blake3::hash(b"opacus_h_generator_v1");
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(hash.as_bytes());
    RistrettoPoint::from_uniform_bytes(&buf)
}

impl Commitment {
    pub fn commit<R: RngCore + CryptoRng>(amount: u64, rng: &mut R) -> (Self, Scalar) {
        let blinding = Scalar::random(rng);
        Self::commit_with_blinding(amount, &blinding)
    }

    pub fn commit_with_blinding(amount: u64, blinding: &Scalar) -> (Self, Scalar) {
        let amount_scalar = Scalar::from(amount);
        let point = amount_scalar * RISTRETTO_BASEPOINT_POINT + blinding * generator_h();
        (
            Self {
                point: point.compress(),
            },
            *blinding,
        )
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }

    pub fn add(&self, other: &Commitment) -> Commitment {
        let p1 = self.point.decompress().expect("valid point");
        let p2 = other.point.decompress().expect("valid point");
        Commitment {
            point: (p1 + p2).compress(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn homomorphic_add() {
        let mut rng = OsRng;
        let (c1, b1) = Commitment::commit(100, &mut rng);
        let (c2, b2) = Commitment::commit(50, &mut rng);
        let sum = c1.add(&c2);
        let (expected, _) = Commitment::commit_with_blinding(150, &(b1 + b2));
        assert_eq!(sum.point, expected.point);
    }
}
