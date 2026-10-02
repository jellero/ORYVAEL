use rust_broker_demo::classify;

#[test]
fn deterministic_seed_sweep() {
    for seed in 0_u16..=255 {
        let mut input = Vec::new();
        for index in 0_usize..128 {
            input.push(((usize::from(seed) * 31 + index * 17) & 0xff) as u8);
            assert!(classify(&input) < 17);
        }
    }
}
