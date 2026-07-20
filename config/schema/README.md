# Generated schemas

The legacy signed-policy contract and installed workflow contract are generated from their strict Rust
types:

```sh
cargo run --locked --bin rdashboard-schema -- --write config/schema/project-manifest-v1.json
cargo run --locked --bin rdashboard-schema -- --write config/schema/project-manifest-v2.json
```

Review generated changes. `bin/ci` checks that the committed schema matches the Rust type.
