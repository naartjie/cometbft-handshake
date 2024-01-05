const SIZE: usize = 12;
const COUNTER_MAX: u128 = 2 ^ (12 * 8);

#[derive(Default)]
pub struct Nonce(u128);

impl Nonce {
    pub fn increment(&mut self) {
        let next_counter = self.0 + 1;
        assert!(next_counter < COUNTER_MAX, "nonce overflow");

        self.0 = next_counter;
    }

    #[inline]
    pub fn value(&self) -> [u8; SIZE] {
        let mut bytes = [0u8; SIZE];
        bytes.copy_from_slice(&self.0.to_le_bytes()[..SIZE]);
        bytes
    }
}
