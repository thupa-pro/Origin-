# Formal Verification — Origin Network

| Directory | Tool | Scope |
|-----------|------|-------|
| `tla/` | TLA+ / TLC Model Checker | IVG CRDT merge consistency, VRM channel safety |
| `coq/` | Coq Proof Assistant | Serialization bijections (binary ↔ text format) |
| `kani/` | Kani Rust Verifier | Bounded model checking on core parser and binary layout |

## Running

```bash
# TLA+ (requires TLA+ Toolbox or tla2tools.jar)
cd tla && java -cp tla2tools.jar tlc2.TLC IvgCrdt.tla

# Kani (requires cargo-kani)
cd ../kani && cargo kani --harness verify_parse -- -Z stderr

# Coq (requires coqc)
cd ../coq && coqc SerializationBijection.v
```
