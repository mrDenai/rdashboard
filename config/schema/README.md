# Generated schemas

`project-manifest-v1.json` is generated from the strict Rust contract:

```sh
cargo run --locked --bin rdashboard-schema -- --write config/schema/project-manifest-v1.json
```

Review generated changes. `bin/ci` checks that the committed schema matches the Rust type.
