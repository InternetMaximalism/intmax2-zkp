use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BitPath {
    length: u32,
    value: u64,
}

impl BitPath {
    pub fn new(length: u32, value: u64) -> Self {
        BitPath { length, value }
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn len(&self) -> u32 {
        self.length
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn push(&mut self, bit: bool) {
        self.value |= (bit as u64) << self.length;
        self.length += 1;
    }

    pub fn pop(&mut self) -> Option<bool> {
        if self.length == 0 {
            return None;
        }
        let bit = (self.value >> (self.length - 1)) & 1;
        // mask out the bit
        self.value &= !(1 << (self.length - 1));
        self.length -= 1;
        Some(bit == 1)
    }

    pub fn to_bits_le(&self) -> Vec<bool> {
        let mut s = *self;
        let mut bits = Vec::new();
        while !s.is_empty() {
            bits.push(s.pop().unwrap());
        }
        bits.reverse(); // reverse to get little-endian bits
        bits
    }

    pub fn from_bits_le(bits: &[bool]) -> Self {
        let mut path = BitPath::default();
        for bit in bits {
            path.push(*bit);
        }
        path
    }

    pub fn reverse(&mut self) {
        let mut bits = self.to_bits_le();
        bits.reverse();
        *self = BitPath::from_bits_le(&bits);
    }

    pub fn sibling(&self) -> Self {
        // flip the last bit
        let mut path = *self;
        let last = path.len() - 1;
        path.value ^= 1 << last;
        path
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn decode(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng as _;

    use super::*;

    #[test]
    fn test_bit_path() {
        let mut path = BitPath::new(0, 0);
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
        assert_eq!(path.value(), 0);

        path.push(true);
        assert!(!path.is_empty());
        assert_eq!(path.len(), 1);
        assert_eq!(path.value(), 1);

        path.push(false);
        assert!(!path.is_empty());
        assert_eq!(path.len(), 2);
        assert_eq!(path.value(), 1);

        let bits = path.to_bits_le();
        assert_eq!(bits, vec![true, false]);
        let recovered_path = BitPath::from_bits_le(&bits);
        assert_eq!(recovered_path, path);

        assert_eq!(path.pop(), Some(false));
        assert!(!path.is_empty());
        assert_eq!(path.len(), 1);
        assert_eq!(path.value(), 1);

        assert_eq!(path.pop(), Some(true));
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
        assert_eq!(path.value(), 0);

        assert_eq!(path.pop(), None);
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
        assert_eq!(path.value(), 0);
    }

    #[test]
    fn test_bit_path_reverse() {
        let path = BitPath::new(10, 5);
        let encoded = path.encode();
        let decoded = BitPath::decode(&encoded);
        assert_eq!(decoded, path);

        println!("{:?}", encoded.len());
    }

    #[test]
    fn test_sibling() {
        let path = BitPath::new(10, 6);
        let sibling = path.sibling();
        {
            let path_bits = path.to_bits_le();
            let mut path = path_bits.clone();
            let last = path.len() - 1;
            path[last] = !path[last];
            let sibling2 = BitPath::from_bits_le(&path);
            assert_eq!(sibling, sibling2);
        }
    }

    #[test]
    fn random_vec() {
        let mut rng = rand::thread_rng();
        let mut popped_bits = (0..10).map(|_| rng.gen_bool(0.5)).collect::<Vec<_>>();
        let mut popped_path = BitPath::from_bits_le(&popped_bits);

        popped_bits.pop();
        popped_path.pop();

        let popped_path_bits = popped_path.to_bits_le();
        assert_eq!(popped_bits, popped_path_bits);
    }
}
