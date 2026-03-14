> **Note:** This README was written by an AI agent.

# bff

A Rust implementation of Binary Fuse Filters.

## What is a Binary Fuse Filter?

A **Binary Fuse Filter** is a probabilistic data structure that enables fast approximate set membership testing — checking whether an element is part of a set — with minimal memory usage.

It works by computing a fingerprint for each item, along with multiple hash functions that map items to positions in an array. This allows for compact storage while maintaining fast queries.

### How It Compares

Binary Fuse Filters were introduced in a 2022 paper by Graf and Lemire ([arXiv:2201.01174](https://arxiv.org/abs/2201.01174), published in ACM Journal of Experimental Algorithmics). They improve upon earlier structures:

- **Bloom filters** achieve ~44% of the theoretical storage lower bound
- **XOR filters** improve to ~23% of the bound
- **Binary Fuse Filters** get within ~13% of the theoretical minimum — without sacrificing query speed

This makes them faster and more space-efficient than Bloom filters and earlier alternatives like XOR filters and Cuckoo filters.

## Use Cases

- Avoiding expensive disk or network lookups by filtering queries
- Fast set membership checks with low memory footprint
- Applications like password breach checking, network routing, and caching

## References

- Graf, T., & Lemire, D. (2022). "Binary Fuse Filters: Fast and Smaller Than Xor Filters." *ACM Journal of Experimental Algorithmics*. https://dl.acm.org/doi/10.1145/3510449
- Original paper: https://arxiv.org/abs/2201.01174
- Reference C++ implementation: https://github.com/FastFilter/xor_singleheader
