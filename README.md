# Tiresias: Scalable, Maliciously Secure Threshold Paillier

Pure-Rust implementation of the UC-secure "Tiresias: Scalable, Maliciously Secure Threshold Paillier" paper by:

- Offir Friedman (dWallet Labs)
- Avichai Marmor (dWallet Labs)
- Dolev Mutzari (dWallet Labs)
- Yehonatan Cohen Scaly (dWallet Labs)
- Yuval Spiizer (dWallet Labs)
- Avishay Yanai

This implementation relies on [`crypto_bigint`](https://github.com/RustCrypto/crypto-bigint) for constant-time big
integer arithmetics whenever dealing with key material or any other secret information.  
With the `parallel` feature, we rely on [`rayon`](https://github.com/rayon-rs/rayon) for data parallelism, which, as
shown theoretically in the paper and experimentally by our `benchmarking` feature, works extremely well in this scheme.

## Setup & Running
 
- See [Makefile](Makefile)
