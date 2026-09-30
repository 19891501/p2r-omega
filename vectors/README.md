# Deterministic V1 vectors

`p2r-valid.json` is a valid signed P2R object using the fixed test key `alice`.
`p2r-tampered.json` changes the effect amount without changing the original digest/signature and must fail.
`receipt-valid.json` is a signed receipt using the fixed test key `observer`.
`universe.json` is the resolved evidence universe used by the P2R vector.
`keyring.json` contains only public keys.

The private test seeds used to generate the vectors are kept only inside `scripts/generate_vectors.py` and are not production credentials.
