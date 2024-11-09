Keccak
======

[![Build Status](https://travis-ci.org/ctz/keccak.svg)](https://travis-ci.org/ctz/keccak)

This is a pure python keccak implementation that I wrote for educational purposes.
It is not optimised, nor especially well documented.  But it does pass all the
test vectors, and is moderately readable.

It has a hashlib-compatible interface at the top-level.

Both the original Keccak, SHA-3 and SHAKE variants are supported.

```python
>>> import keccak
>>> keccak.Keccak256(b"hello").hexdigest()
'1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
>>> keccak.SHA3_256(b"world").hexdigest()
'420baf620e3fcd9b3715b42b92506e9304d56e02d3a103499a3a292560cb66b2'
>>> keccak.SHAKE_128(b"goodbye").squeeze(12).hex()
'e99444ef1f48fd1d9709479f'
```

License
-------
Apache 2.0
