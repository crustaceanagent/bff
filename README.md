> **Note:** This README was written by an AI agent.

# bff

A Rust implementation of Binary Fuse Filters.

## What is a Binary Fuse Filter?

A **Binary Fuse Filter** is a probabilistic data structure that enables fast approximate set membership testing — checking whether an element is part of a set — with minimal memory usage.

### Core Idea

Binary fuse filters build on the **XOR filter** approach, which treats the membership problem as a system of XOR equations. Instead of storing a bit array like Bloom filters, XOR filters store **fingerprints** — small hash values derived from each element.

The fundamental relationship is:

$$
B[h_0(x)] \oplus B[h_1(x)] \oplus B[h_2(x)] = \text{fingerprint}(x)
$$

Where:
- $x$ is an element from the set $S$
- $h_0, h_1, h_2$ are three hash functions mapping elements to array indices
- $B$ is the fingerprint array
- $\oplus$ denotes XOR

### From XOR to Binary Fuse

Binary fuse filters improve on XOR filters by using a **fused** architecture — combining multiple smaller fingerprint arrays into one. This reduces storage overhead while maintaining query speed.

The key insight is that XOR filters require approximately $1.23 \times |S|$ fingerprint slots. Binary fuse filters achieve better compression by:

1. Using **segmentation**: Dividing the data into segments processed independently
2. **Layered construction**: Building a hierarchy of smaller filters that work together
3. **Simplified hash functions**: Replacing the three-hash approach with a more compact two-hash scheme

## Mathematical Background

### Theoretical Storage Lower Bound

The information-theoretic lower bound for storing membership information for a set of size $n$ is $\log_2 \binom{2^n}{n} \approx n \log_2 (e/n)$ bits (using Stirling's approximation).

Normalized per element, this approaches $\log_2(e) \approx 1.44$ bits as $n \to \infty$.

### Space Efficiency Comparison

| Filter Type | Bits per Element | % of Lower Bound |
|-------------|------------------|------------------|
| Bloom Filter | ~7-10 | ~44% |
| XOR Filter | ~4 | ~23% |
| Binary Fuse Filter | ~3.2 | ~13% |
| Binary Fuse+ (slower query) | ~3.0 | ~8% |

### The Hash Functions

For a set $S$ of 64-bit integers, we use three hash functions:

$$
h_i(x) = (f_i(x) \bmod 2^k) + offset_i
$$

Where $f_i$ is a fingerprint function and $k$ is chosen based on the desired false-positive rate. The offsets ensure the three hash functions map to different segments of the array.

### Fingerprint Computation

Given an element $x$, we compute a fingerprint as:

$$
\text{fingerprint}(x) = \text{MurmurHash3}(x) \oplus x
$$

This ensures the fingerprint depends on both the hash and the original value, reducing collisions.

## Worked Example

Consider a simple set $S = \{3, 7, 12\}$ with 8-bit fingerprints and an array of size 4.

**Step 1: Compute hashes**

For each element, compute three positions using hash functions. Suppose:
- $h_0(3) = 0, h_1(3) = 1, h_2(3) = 3$
- $h_0(7) = 1, h_1(7) = 2, h_2(7) = 3$
- $h_0(12) = 0, h_1(12) = 2, h_2(12) = 3$

**Step 2: Compute fingerprints**

Let $\text{fingerprint}(3) = 0b1011$, $\text{fingerprint}(7) = 0b0101$, $\text{fingerprint}(12) = 0b1110$.

**Step 3: Solve the XOR system**

We need to find array values $B[0], B[1], B[2], B[3]$ such that:

For $x = 3$: $B[0] \oplus B[1] \oplus B[3] = 0b1011$  
For $x = 7$: $B[1] \oplus B[2] \oplus B[3] = 0b0101$  
For $x = 12$: $B[0] \oplus B[2] \oplus B[3] = 0b1110$

This is a system of linear equations over GF(2). Solving (conceptually):

1. Start with the last element added (12): $B[0] = \text{fingerprint}(12) \oplus B[2] \oplus B[3]$
2. Substitute to find remaining values
3. Final solution: $B[0] = 0b0110, B[1] = 0b1101, B[2] = 0b1000, B[3] = 0b0001$

**Step 4: Query**

To query for element $x = 7$:
- Compute positions: $h_0(7) = 1, h_1(7) = 2, h_2(7) = 3$
- Compute XOR: $B[1] \oplus B[2] \oplus B[3] = 0b1101 \oplus 0b1000 \oplus 0b0001 = 0b0101$
- Compare with stored fingerprint: $0b0101 == \text{fingerprint}(7)$ ✓

For a non-member (e.g., $x = 99$ with fingerprint $0b0011$):
- Positions might map to values that XOR to something else
- If the computed XOR doesn't match any stored fingerprint, we know it's definitely not in the set
- If it matches *some* fingerprint by coincidence, we get a **false positive**

### False Positive Rate

With $b$ bits per fingerprint, the false positive rate is approximately:

$$
\text{FPR} \approx \frac{1}{2^b}
$$

The standard binary fuse implementations use:
- **binary_fuse8**: 8-bit fingerprints → FPR ≈ 0.39% (1/256)
- **binary_fuse16**: 16-bit fingerprints → FPR ≈ 0.0015% (1/65536)

## Construction Algorithm

The binary fuse filter construction proceeds as follows:

1. **Hash mapping**: Compute $h_0, h_1, h_2$ for each element, creating a mapping graph
2. **Peeling**: Identify and remove "peelable" nodes (those with only one incident edge) in a stack-based process
3. **Backtracking**: Solve for the remaining values by reversing the peeling order
4. **Verification**: Confirm all elements satisfy the fingerprint equation

This approach ensures determinism and guarantees the array values are consistent.

## Use Cases

- Avoiding expensive disk or network lookups by filtering queries
- Fast set membership checks with low memory footprint
- Applications like password breach checking, network routing, and caching
- Highly compact, compressible membership structures for storage-constrained environments

## Implementation Notes

- Works with 64-bit integers — strings/other data types require hashing to 64-bit first
- Construction requires ~24 bytes of temporary memory per element
- Filters are naturally compressible (gzip, zstd) — unlike Bloom filters
- Supports both unpacked (faster) and packed (smaller) serialization formats

## References

- Graf, T., & Lemire, D. (2022). "Binary Fuse Filters: Fast and Smaller Than Xor Filters." *ACM Journal of Experimental Algorithmics*. https://dl.acm.org/doi/10.1145/3510449
- Original paper: https://arxiv.org/abs/2201.01174
- Graf, T., & Lemire, D. (2020). "Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters." *ACM Journal of Experimental Algorithmics*. https://arxiv.org/abs/1912.08258
- Reference C++ implementation: https://github.com/FastFilter/xor_singleheader
