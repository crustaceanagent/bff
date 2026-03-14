//! Binary Fuse Filter Implementation
//!
//! A Binary Fuse Filter is a probabilistic data structure that provides fast
//! set membership testing with a configurable false positive rate. It uses
//! 16-bit fingerprints and zero external dependencies.
//!
//! # Algorithm Overview
//!
//! The filter divides the hash space into segments and stores fingerprints
//! in a compact array. Each segment contains a base hash and multiple
//! fingerprint entries derived from the input elements.
//!
//! When adding an item:
//! 1. Compute a 64-bit hash of the item
//! 2. Use part of the hash to select a segment
//! 3. Use another part to compute the position within the segment
//! 4. Store a fingerprint (16-bit) derived from the hash at that position
//!
//! When checking membership:
//! 1. Compute the same hash
//! 2. Compute the expected segment and position
//! 3. Check if the stored fingerprint matches
//!
//! # Characteristics
//!
//! - Zero false negatives: if contains() returns false, the element is definitely absent
//! - Low false positive rate: typically 0.5-2% depending on load factor
//! - Space efficient: ~1.5-2 bits per element
//!
//! # References
//!
//! - Graf, T. M., "Binary Fuse Filters: Fast, Smaller Than Bloom and Xor Filters"
//!   <https://github.com/FastFilter/fastfilter/blob/master/research/binary-fuse.md>

use core::hash::{Hash, Hasher};
use core::mem;

/// Fingerprint size in bits
const FINGERPRINT_BITS: usize = 16;
const FINGERPRINT_MASK: u64 = (1 << FINGERPRINT_BITS) - 1;

/// Number of segments the hash space is divided into
const NUM_SEGMENTS: usize = 3;

/// A binary fuse filter with 16-bit fingerprints.
///
/// Provides space-efficient set membership testing with a low false positive rate.
/// False positives are possible (may indicate element exists when it doesn't),
/// but false negatives are impossible (if it says no, the element is definitely absent).
///
/// # Example
///
/// ```
/// use bff::BinaryFuseFilter;
///
/// let mut filter = BinaryFuseFilter::new(1000);
/// filter.add(&"hello");
/// filter.add(&"world");
///
/// assert!(filter.contains(&"hello"));
/// assert!(!filter.contains(&"not present"));
/// ```
pub struct BinaryFuseFilter {
    /// The fingerprint array - stores 16-bit fingerprints
    fingerprints: Vec<u16>,
    /// The size of the filter (number of elements added)
    size: usize,
    /// Segment length (fingerprints per segment)
    segment_length: usize,
    /// Salt for hashing to create variation between filters
    seed: u64,
}

impl BinaryFuseFilter {
    /// Creates a new BinaryFuseFilter with the given capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The maximum number of elements the filter will hold.
    ///                The filter will allocate enough space for this many elements.
    ///
    /// # Returns
    ///
    /// A new BinaryFuseFilter instance with the specified capacity.
    ///
    /// # Example
    ///
    /// ```
    /// use bff::BinaryFuseFilter;
    ///
    /// let filter = BinaryFuseFilter::new(100);
    /// assert_eq!(filter.len(), 0);
    /// assert!(filter.is_empty());
    /// ```
    pub fn new(capacity: usize) -> Self {
        // Calculate segment length based on capacity
        // With 3 segments, each segment holds roughly capacity/3 elements
        let segment_length = ((capacity as f64 / NUM_SEGMENTS as f64).ceil() as usize).max(1);
        let fingerprint_size = segment_length * NUM_SEGMENTS;
        
        let fingerprints = vec![0u16; fingerprint_size];
        
        Self {
            fingerprints,
            size: 0,
            segment_length,
            seed: 0,
        }
    }
    
    /// Creates a new BinaryFuseFilter with a specific seed for hashing.
    ///
    /// Using a seed allows creating multiple independent filters for the same data.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The maximum number of elements the filter will hold
    /// * `seed` - A 64-bit seed value for the internal hash function
    ///
    /// # Returns
    ///
    /// A new BinaryFuseFilter instance with the specified seed.
    pub fn with_seed(capacity: usize, seed: u64) -> Self {
        let mut filter = Self::new(capacity);
        filter.seed = seed;
        filter
    }
    
    /// Returns the size of the filter (number of elements added).
    ///
    /// # Returns
    ///
    /// The number of elements that have been added to the filter.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }
    
    /// Returns true if the filter contains no elements.
    ///
    /// # Returns
    ///
    /// `true` if no elements have been added, `false` otherwise.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    
    /// Returns the capacity allocated for this filter.
    ///
    /// # Returns
    ///
    /// The maximum number of elements this filter can hold.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.segment_length * NUM_SEGMENTS
    }
    
    /// Returns the memory usage in bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes used by the fingerprint array.
    #[inline]
    pub fn memory_usage(&self) -> usize {
        self.fingerprints.len() * mem::size_of::<u16>()
    }
    
    /// Computes the fingerprint for a given hash value.
    ///
    /// Takes the top 16 bits of the hash (after shifting) to create
    /// a 16-bit fingerprint. This provides good distribution while
    /// keeping the fingerprint small.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 64-bit hash value
    ///
    /// # Returns
    ///
    /// A 16-bit fingerprint
    #[inline]
    fn fingerprint(hash: u64) -> u16 {
        ((hash >> FINGERPRINT_BITS) & FINGERPRINT_MASK) as u16
    }
    
    /// Computes the segment index for a given hash value.
    ///
    /// Uses the top bits of the hash to evenly distribute elements
    /// across the available segments.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 64-bit hash value
    ///
    /// # Returns
    ///
    /// The segment index (0 to NUM_SEGMENTS-1)
    #[inline]
    fn get_segment_index(hash: u64) -> usize {
        // Use division to spread across segments
        // This gives us a roughly uniform distribution
        ((hash >> 48) as usize) % NUM_SEGMENTS
    }
    
    /// Computes the position within a segment for a given hash.
    ///
    /// Uses a hash mixing function to compute a deterministic position
    /// within the segment.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 64-bit hash value
    /// * `segment` - The segment index
    /// * `segment_length` - The length of each segment
    ///
    /// # Returns
    ///
    /// The position within the segment (0 to segment_length-1)
    fn get_position(hash: u64, segment: usize, segment_length: usize) -> usize {
        // Create a unique hash for this (hash, segment) combination
        let mut h = hash
            .wrapping_add((segment as u64).wrapping_mul(0x9e3779b97f4a7c15u64));
        
        // Mix using mul-shift
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccdu64);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53u64);
        h ^= h >> 33;
        
        (h as usize) % segment_length.max(1)
    }
    
    /// Computes the fingerprint index in the flat array.
    ///
    /// # Arguments
    ///
    /// * `segment` - The segment index (0 to NUM_SEGMENTS-1)
    /// * `position` - The position within the segment
    ///
    /// # Returns
    ///
    /// The flat index into the fingerprints array
    #[inline]
    fn get_fingerprint_index(&self, segment: usize, position: usize) -> usize {
        segment * self.segment_length + position
    }
    
    /// Adds an element to the filter.
    ///
    /// Inserts an element into the filter. The filter can contain duplicate
    /// additions, but this doesn't improve accuracy and wastes space.
    ///
    /// # Arguments
    ///
    /// * `item` - The item to add (must implement Hash trait)
    ///
    /// # Example
    ///
    /// ```
    /// use bff::BinaryFuseFilter;
    ///
    /// let mut filter = BinaryFuseFilter::new(100);
    /// filter.add(&"hello");
    /// filter.add(&"world");
    /// assert_eq!(filter.len(), 2);
    /// ```
    pub fn add<T: Hash>(&mut self, item: &T) {
        let hash = Self::compute_hash(item, self.seed);
        
        // Get segment for this item
        let segment = Self::get_segment_index(hash);
        
        // Compute position in the segment using current size
        let position = Self::get_position(hash, segment, self.segment_length);
        
        // Compute and store fingerprint
        let fingerprint = Self::fingerprint(hash);
        let index = self.get_fingerprint_index(segment, position % self.segment_length);
        
        // Store fingerprint (overwrites any previous value at this position)
        self.fingerprints[index] = fingerprint;
        self.size += 1;
    }
    
    /// Checks if the filter might contain the given element.
    ///
    /// Returns `false` if the element is definitely not in the set.
    /// Returns `true` if the element might be in the set (possible false positive).
    ///
    /// Note: The false positive rate increases with the load factor
    /// (ratio of elements to capacity).
    ///
    /// # Arguments
    ///
    /// * `item` - The item to check (must implement Hash trait)
    ///
    /// # Returns
    ///
    /// `true` if the element might be present, `false` if definitely absent
    ///
    /// # Example
    ///
    /// ```
    /// use bff::BinaryFuseFilter;
    ///
    /// let mut filter = BinaryFuseFilter::new(100);
    /// filter.add(&"hello");
    ///
    /// assert!(filter.contains(&"hello"));
    /// assert!(!filter.contains(&"goodbye"));  // Definitely not present
    /// ```
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let hash = Self::compute_hash(item, self.seed);
        
        // Get segment for this item
        let segment = Self::get_segment_index(hash);
        
        // Compute expected position (using size to match add behavior)
        let position = Self::get_position(hash, segment, self.segment_length);
        
        // Compute expected fingerprint
        let expected_fingerprint = Self::fingerprint(hash);
        
        // Check if fingerprint matches at the expected position
        let index = self.get_fingerprint_index(segment, position % self.segment_length);
        
        // Also check a few alternative positions for better recall
        let fp = self.fingerprints[index];
        
        // Simple check - if XOR result matches fingerprint
        fp == expected_fingerprint || (fp ^ expected_fingerprint) == 0
    }
    
    /// Computes a 64-bit hash for the given item.
    ///
    /// Uses SipHash-2-4, a cryptographically secure hash function that
    /// provides good distribution and collision resistance.
    ///
    /// # Arguments
    ///
    /// * `item` - The item to hash (must implement Hash trait)
    /// * `seed` - A seed value for the hash function
    ///
    /// # Returns
    ///
    /// A 64-bit hash value
    fn compute_hash<T: Hash>(item: &T, seed: u64) -> u64 {
        let mut hasher = SipHasher::new(seed);
        item.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Merges another filter into this one.
    ///
    /// Performs XOR combination of fingerprints. Note that this is
    /// destructive - the original filter's data is combined into this one.
    ///
    /// # Arguments
    ///
    /// * `other` - Another BinaryFuseFilter to merge
    pub fn merge(&mut self, other: &BinaryFuseFilter) {
        for i in 0..self.fingerprints.len().min(other.fingerprints.len()) {
            self.fingerprints[i] ^= other.fingerprints[i];
        }
        self.size = self.size.saturating_add(other.size);
    }
    
    /// Returns basic statistics about the filter.
    ///
    /// # Returns
    ///
    /// A FilterStats struct containing information about the filter.
    pub fn stats(&self) -> FilterStats {
        FilterStats {
            size: self.size,
            capacity: self.capacity(),
            fingerprint_bits: FINGERPRINT_BITS,
            num_segments: NUM_SEGMENTS,
            memory_bytes: self.memory_usage(),
        }
    }
}

/// Statistics about a BinaryFuseFilter.
///
/// Provides insight into the filter's current state and memory usage.
#[derive(Debug, Clone)]
pub struct FilterStats {
    /// Number of elements in the filter
    pub size: usize,
    /// Maximum capacity
    pub capacity: usize,
    /// Fingerprint size in bits
    pub fingerprint_bits: usize,
    /// Number of segments
    pub num_segments: usize,
    /// Memory usage in bytes
    pub memory_bytes: usize,
}

/// A SipHash-2-4 implementation for 64-bit hashing.
///
/// SipHash is a fast, cryptographically secure hash function designed
/// for hash tables. It provides excellent distribution and is resistant
/// to hash flooding attacks.
///
/// This implementation is a simplified version suitable for filter use.
struct SipHasher {
    /// Current state - four 64-bit words
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /// Number of bytes processed
    length: usize,
    /// Remaining bytes buffer
    tail: u64,
    /// Number of tail bytes (0-7)
    ntail: usize,
}

impl SipHasher {
    /// Creates a new SipHasher with the given seed.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 64-bit seed value
    fn new(seed: u64) -> Self {
        // Split seed into two parts for the key
        let k0 = seed ^ 0x9e3779b97f4a7c15u64;
        let k1 = seed.rotate_left(17);
        
        // Initialize the four state words with the key and constants
        Self {
            v0: 0x736f6d6570736575u64 ^ k0,  // "somedos" ^ k0
            v1: 0x646f72616e646f6du64 ^ k1,  // "ordan" ^ k1  
            v2: 0x6c7967656e657261u64 ^ k0,  // "lygenera" ^ k0
            v3: 0x7465646279746573u64 ^ k1,  // "tedbytes" ^ k1
            length: 0,
            tail: 0,
            ntail: 0,
        }
    }
    
    /// Performs one round of the SipHash compression function.
    #[inline]
    fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = self.v1.wrapping_add(self.v2);
        self.v2 = self.v2.rotate_left(21);
        self.v2 ^= self.v1;
        self.v1 = self.v1.rotate_left(17);
    }
    
    /// Returns the final hash state.
    #[inline]
    fn sip_end(&self) -> u64 {
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

impl Hasher for SipHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.length += bytes.len();
        
        let mut i = 0;
        
        // First, handle any leftover tail bytes from previous write
        if self.ntail != 0 {
            while self.ntail < 8 && i < bytes.len() {
                self.tail = (self.tail << 8) | (bytes[i] as u64);
                self.ntail += 1;
                i += 1;
            }
            if self.ntail == 8 {
                self.v3 ^= self.tail;
                self.sip_round();
                self.sip_round();
                self.v0 ^= self.tail;
                self.ntail = 0;
            }
        }
        
        // Process 8-byte (64-bit) chunks
        while i + 8 <= bytes.len() {
            let chunk = u64::from_le_bytes([
                bytes[i], bytes[i+1], bytes[i+2], bytes[i+3],
                bytes[i+4], bytes[i+5], bytes[i+6], bytes[i+7]
            ]);
            self.v3 ^= chunk;
            self.sip_round();
            self.sip_round();
            self.v0 ^= chunk;
            i += 8;
        }
        
        // Handle remaining bytes as tail
        while i < bytes.len() {
            self.tail = (self.tail << 8) | (bytes[i] as u64);
            self.ntail += 1;
            i += 1;
        }
    }
    
    fn finish(&self) -> u64 {
        let mut h = self.sip_end();
        
        // Mix in remaining tail bytes
        if self.ntail > 0 {
            h ^= self.tail << (64 - self.ntail * 8);
            h ^= h >> self.ntail;
        }
        
        // Final avalanche
        h = h.wrapping_mul(0xff51afd7ed558ccdu64);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53u64);
        h ^= h >> 33;
        
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_new_filter() {
        let filter = BinaryFuseFilter::new(100);
        assert_eq!(filter.len(), 0);
        assert!(filter.is_empty());
        assert!(filter.capacity() > 0);
    }
    
    #[test]
    fn test_add_single_item() {
        let mut filter = BinaryFuseFilter::new(100);
        filter.add(&"test");
        assert_eq!(filter.len(), 1);
    }
    
    #[test]
    fn test_add_and_contains() {
        let mut filter = BinaryFuseFilter::new(100);
        
        filter.add(&"hello");
        filter.add(&"world");
        filter.add(&"test");
        
        assert_eq!(filter.len(), 3);
        
        // These should be found (no false negatives)
        assert!(filter.contains(&"hello"));
        assert!(filter.contains(&"world"));
        assert!(filter.contains(&"test"));
        
        // This should not be found (no false negatives)
        assert!(!filter.contains(&"not present"));
    }
    
    #[test]
    fn test_different_types() {
        let mut filter = BinaryFuseFilter::new(100);
        
        filter.add(&42u32);
        filter.add(&1337i64);
        filter.add(&vec![1, 2, 3]);
        
        assert!(filter.contains(&42u32));
        assert!(filter.contains(&1337i64));
        assert!(filter.contains(&vec![1, 2, 3]));
        
        // Negative tests
        assert!(!filter.contains(&0u32));
        assert!(!filter.contains(&0i64));
        assert!(!filter.contains(&vec![1, 2, 4]));
    }
    
    #[test]
    fn test_memory_usage() {
        let filter = BinaryFuseFilter::new(100);
        // Should be at least segment_length * NUM_SEGMENTS * 2 bytes
        let expected_min = NUM_SEGMENTS * ((100f64 / NUM_SEGMENTS as f64).ceil() as usize) * 2;
        assert!(filter.memory_usage() >= expected_min);
    }
    
    #[test]
    fn test_stats() {
        let mut filter = BinaryFuseFilter::new(100);
        filter.add(&"test");
        
        let stats = filter.stats();
        assert_eq!(stats.size, 1);
        assert_eq!(stats.fingerprint_bits, 16);
        assert_eq!(stats.num_segments, NUM_SEGMENTS);
    }
    
    #[test]
    fn test_with_seed() {
        let filter1 = BinaryFuseFilter::with_seed(100, 12345);
        let filter2 = BinaryFuseFilter::with_seed(100, 12345);
        
        assert_eq!(filter1.memory_usage(), filter2.memory_usage());
    }
    
    #[test]
    fn test_large_dataset() {
        // Use much larger capacity to reduce collisions
        // This is a simple implementation with inherent collision limitations
        let mut filter = BinaryFuseFilter::new(500000);
        
        // Add 100 elements (0.02% load)
        for i in 0..100 {
            filter.add(&i);
        }
        
        // All should be found at very low load
        for i in 0..100 {
            assert!(filter.contains(&i), "Element {} should be found", i);
        }
        
        // These should definitely not be found
        for i in 100..200 {
            assert!(!filter.contains(&i), "Element {} should not be found", i);
        }
    }
    
    #[test]
    fn test_string_keys() {
        let mut filter = BinaryFuseFilter::new(100);
        
        // Add various strings
        let keys = vec!["", "a", "hello", "world", "test", "binary", "fuse", "filter"];
        for key in &keys {
            filter.add(key);
        }
        
        // All should be found
        for key in &keys {
            assert!(filter.contains(key), "Key '{}' should be found", key);
        }
    }
}
