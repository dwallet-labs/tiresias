# Tiresias: Scalable, Maliciously Secure Threshold Paillier

A pure-Rust implementation of the
UC-secure ["Tiresias: Large Scale, Maliciously Secure Threshold Paillier"](https://eprint.iacr.org/2023/998) paper by:

- Offir Friedman (dWallet Labs)
- Avichai Marmor (dWallet Labs)
- Dolev Mutzari (dWallet Labs)
- Yehonatan Cohen Scaly (dWallet Labs)
- Yuval Spiizer (dWallet Labs)
- Avishay Yanai

This is an implementation of the *threshold decryption* protocol only. For *distributed key generation*, a protocol like
*Diogenes* ([paper](https://eprint.iacr.org/2020/374), [implementation](https://github.com/JustinDrake/LigeroRSA))
should be used.

It is worth mentioning that we also support the *trusted dealer* setting for which one can see examples in our testing &
benchmarking code that uses `secret_sharing/shamir` to deal a secret.

## Security

This implementation relies on [`crypto_bigint`](https://github.com/RustCrypto/crypto-bigint) for constant-time big
integer arithmetics whenever dealing with key material or any other secret information.

We have gone through a rigorous internal auditing process throughout development, requiring the approval of two
additional cryptographers and one additional programmer in every pull request.
That being said, this code has not been audited by a third party yet; use it at your own risk.

## Releases

This code has no official releases yet, and we reserve the right to change some of the public API until then.

## Performance & Benchmarking

Our code achieves unprecedented scale & performance, with a throughput of about **50 and 3.6 decryptions per _second_**,
when run over a network of **100 and 1000 parties**, respectively.

We have set up an automated GitHub action for benchmarking over an EC2 C6i machine, the result of which could
be [viewed here](https://github.com/odsy-network/tiresias/actions/runs/5363804053/jobs/9731618097).

With the `parallel` feature, we rely on [`rayon`](https://github.com/rayon-rs/rayon) for data parallelism, which, as
shown theoretically in the paper and experimentally, works extremely well in this scheme.

## Setup & Running

See [Makefile](Makefile)
