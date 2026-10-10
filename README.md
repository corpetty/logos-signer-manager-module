# logos-signer-manager-module

`signer_manager_module` takes signature requests from any named module, shows them to a person
through the signer app, and has the account's signer sign: `keystore_module` for keys kept in files,
and one module per hardware wallet, each behind
[`logos.signer/1`](https://github.com/logos-co/logos-signer-interface). It holds no keys. It reads,
renders and commits to every request, computes every digest, and checks every signature against
the account's public material before anyone can collect a result.

The approval API is `keystore_module`'s, with the same names and shapes:
- **Requesters**, any named module: `request_approval`, `approval_status`, `fetch_result`,
  `ack_result` and `cancel_approval`.
- **The approver**, the signer app: `pending`, `acknowledge`, `approve` and `reject`.

A requester or an approver moving here changes only the module it calls. The results are byte for
byte what the keystore returned when it signed itself.

`accounts` lists every signer's accounts, without xpubs. `signers` says which signer modules are
consulted. `configure` names the approvers, the custodians and the signers. Unconfigured, it consults
the keystore, then the Keycard Shell's and the Keycard's modules when they are installed.

See [`docs/specs.md`](docs/specs.md) for the reference, and
[`doctests/signer-manager-runtime.test.yaml`](doctests/signer-manager-runtime.test.yaml) for the
round trip through `logoscore`.

```sh
cd rust-lib && cargo test --no-default-features
nix build
```

[`tools/regtest`](tools/regtest) signs native segwit and taproot sends through the manager and has a
regtest bitcoind accept them, once over hashes and once by a mock device handed each PSBT whole.

Licensed under MIT or Apache-2.0.
