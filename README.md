[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/UtC.NET/blob/main/LICENSE)

# UtC.NET
[Bellare and Hoang's](https://eprint.iacr.org/2022/268) UtC and HtE[UtC] transforms using ChaCha20-Poly1305 and BLAKE2b.

I will implement CX separately as I find it unlikely to be used with ChaCha20-Poly1305. The other difference is that this implementation produces a 256-bit commitment rather than 128 bits. Thus, it's actually more similar to the [Albertini et al.](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini) CommitKey.
