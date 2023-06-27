# Tiresias: Scalable, Maliciously Secure Threshold Paillier

A pure-Rust implementation of the UC-secure "Tiresias: Large Scale, Maliciously Secure Threshold Paillier" paper by:

- Offir Friedman (dWallet Labs)
- Avichai Marmor (dWallet Labs)
- Dolev Mutzari (dWallet Labs)
- Yehonatan Cohen Scaly (dWallet Labs)
- Yuval Spiizer (dWallet Labs)
- Avishay Yanai

## Security
This implementation relies on [`crypto_bigint`](https://github.com/RustCrypto/crypto-bigint) for constant-time big
integer arithmetics whenever dealing with key material or any other secret information.  

We have gone through a rigorous internal auditing process throughout development, requiring the approval of two additional cryptographers and one additional programmer in every pull request. 
That being said, this code has not been audited by a third party yet; use it at your own risk. 

## Releases
This code has no official releases as of yet, and we reserve ourselves the right to change some of the public API until then.

## Setup & Running

With the `parallel` feature, we rely on [`rayon`](https://github.com/rayon-rs/rayon) for data parallelism, which, as
shown theoretically in the paper and experimentally by our `benchmarking` feature, works extremely well in this scheme.

See [Makefile](Makefile)
