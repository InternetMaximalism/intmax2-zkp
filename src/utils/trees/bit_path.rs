use serde::{Deserialize, Serialize};

/// `BitPath` represents a path in a binary tree as a sequence of bits.
/// 
/// It efficiently stores the path using:
/// - `length`: The number of bits in the path (max 64)
/// - `value`: A u64 where each bit represents a direction in the tree (0 for left, 1 for right)
///
/// This is commonly used in Merkle trees to represent paths from the root to leaves.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BitPath {
    length: u32,
    value: u64,
}

impl BitPath {
    /// Creates a new `BitPath` with the specified length and value.
    ///
    /// # Arguments
    /// * `length` - The number of bits in the path
    /// * `value` - The bit pattern representing the path
    ///
    /// # Returns
    /// A new `BitPath` instance
    pub fn new(length: u32, value: u64) -> Self {
        BitPath { length, value }
    }

    /// Checks if the path is empty (has zero length).
    ///
    /// # Returns
    /// `true` if the path is empty, `false` otherwise
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the number of bits in the path.
    ///
    /// # Returns
    /// The length of the path in bits
    pub fn len(&self) -> u32 {
        self.length
    }

    /// Returns the raw bit value of the path.
    ///
    /// # Returns
    /// The u64 value representing the bit pattern
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Appends a bit to the end of the path.
    ///
    /// # Arguments
    /// * `bit` - The bit to append (`true` for 1, `false` for 0)
    ///
    /// # Note
    /// This operation sets the bit at position `length` and increments the length.
    pub fn push(&mut self, bit: bool) {
        self.value |= (bit as u64) << self.length;
        self.length += 1;
    }

    /// Removes and returns the last bit from the path.
    ///
    /// # Returns
    /// * `Some(bool)` - The removed bit (`true` for 1, `false` for 0)
    /// * `None` - If the path is empty
    ///
    /// # Note
    /// This operation extracts the bit at position `length-1`, 
    /// masks it out from the value, and decrements the length.
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

    /// Converts the path to a vector of bits in little-endian order.
    ///
    /// # Returns
    /// A vector of booleans representing the bits in the path,
    /// where the first element is the least significant bit.
    ///
    /// # Note
    /// This creates a copy of the path and pops bits until empty,
    /// then reverses the result to get little-endian ordering.
    pub fn to_bits_le(&self) -> Vec<bool> {
        let mut s = *self;
        let mut bits = Vec::new();
        while !s.is_empty() {
            bits.push(s.pop().unwrap());
        }
        bits.reverse(); // reverse to get little-endian bits
        bits
    }

    /// Creates a `BitPath` from a vector of bits in little-endian order.
    ///
    /// # Arguments
    /// * `bits` - A slice of booleans representing the bits in little-endian order
    ///
    /// # Returns
    /// A new `BitPath` containing the specified bits
    ///
    /// # Note
    /// Iterates through the bits and pushes each one onto a new path.
    pub fn from_bits_le(bits: &[bool]) -> Self {
        let mut path = BitPath::default();
        for bit in bits {
            path.push(*bit);
        }
        path
    }

    /// Reverses the order of bits in the path.
    ///
    /// # Note
    /// Converts to a bit vector, reverses it, and reconstructs the path.
    /// This effectively flips the path direction in a binary tree.
    pub fn reverse(&mut self) {
        let mut bits = self.to_bits_le();
        bits.reverse();
        *self = BitPath::from_bits_le(&bits);
    }

    /// Returns the sibling path by flipping the last bit.
    ///
    /// # Returns
    /// A new `BitPath` that represents the sibling node in a binary tree
    ///
    /// # Note
    /// In a binary tree, the sibling of a node is found by flipping
    /// the last bit in its path (changing left to right or vice versa).
    pub fn sibling(&self) -> Self {
        // flip the last bit
        let mut path = *self;
        let last = path.len() - 1;
        path.value ^= 1 << last;
        path
    }

    /// Serializes the `BitPath` to a byte vector using bincode.
    ///
    /// # Returns
    /// A vector of bytes representing the serialized path
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    /// Deserializes a `BitPath` from a byte slice using bincode.
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the serialized path
    ///
    /// # Returns
    /// The deserialized `BitPath`
    pub fn decode(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng as _;

    use super::*;

    /// Tests basic functionality of BitPath:
    /// - Creation of an empty path
    /// - Pushing bits
    /// - Converting to and from bit vectors
    /// - Popping bits
    /// - Empty state checks
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

    /// Tests serialization and deserialization of BitPath
    #[test]
    fn test_bit_path_encoding() {
        let path = BitPath::new(10, 5);
        let encoded = path.encode();
        let decoded = BitPath::decode(&encoded);
        assert_eq!(decoded, path);
    }

    /// Tests the bit reversal functionality
    /// 
    /// This test creates a path with value 5 (binary: 0000000101) and length 10,
    /// then reverses it and verifies the resulting bit pattern is correct.
    #[test]
    fn test_bit_path_reverse() {
        let path = BitPath::new(10, 5);
        let mut reversed_path = path.clone();
        reversed_path.reverse();
        let reversed_bits = reversed_path.to_bits_le();
        assert_eq!(
            reversed_bits,
            vec![false, false, false, false, false, false, false, true, false, true]
        );
    }

    /// Tests the sibling path calculation
    /// 
    /// This test verifies that the sibling() method correctly flips the last bit
    /// by comparing it with a manually constructed sibling path.
    #[test]
    fn test_bit_path_sibling() {
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

    /// Tests BitPath with random bit vectors
    /// 
    /// This test creates a random bit vector, converts it to a BitPath,
    /// then pops a bit from both the vector and the path to verify
    /// they remain equivalent after modification.
    #[test]
    fn test_bit_path_random_vec() {
        let mut rng = rand::thread_rng();
        let mut popped_bits = (0..10).map(|_| rng.gen_bool(0.5)).collect::<Vec<_>>();
        let mut popped_path = BitPath::from_bits_le(&popped_bits);

        popped_bits.pop();
        popped_path.pop();

        let popped_path_bits = popped_path.to_bits_le();
        assert_eq!(popped_bits, popped_path_bits);
    }
}
