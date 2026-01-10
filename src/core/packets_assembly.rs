use rand::{rng, Rng, RngCore};
use crate::core::cfg::MessConfig;

pub fn packet_assemble(cfg: &MessConfig, packet: Vec<u8>) -> Vec<u8> {
    let mut rng = rng();
    let mut prefix = Vec::new();
    if !cfg.garbage_amount.is_empty() {
        let packets_amount = rng.random_range(cfg.garbage_amount.clone());
        for _ in 0..packets_amount {
            let size = rng.random_range(cfg.garbage_size.clone());
            prefix.extend((0..size).map(|_| rng.random_range(0..=255)));
        }
    }

    let mut result = Vec::with_capacity(prefix.len() + packet.len());
    result.extend(prefix);
    result.extend(packet);
    result
}