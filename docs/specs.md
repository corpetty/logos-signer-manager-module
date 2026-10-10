# `logos-signer-manager-module` — Reference Specification

## Purpose

`signer_manager_module` takes signature requests from any named module, shows them to a person
through the signer app, and has the account's **signer** sign. A signer is any module that
implements [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface):
`keystore_module` for keys kept in files, and one module per hardware wallet. The manager holds no
keys. It reads, renders and commits to every request, computes every digest itself, hands the
digests to the account's signer, and checks every signature against the account's public material
before anyone can collect a result.

It is phase K1 of the [Shared Keystore Plan](https://claude.ai/artifact/LdbUCDJNW5Ep817xKkvtMf).
The approval API comes from `keystore_module`, with the same method names and shapes, so a
requester or an approver changes only the module it calls.

## How a request moves

1. A named module calls `request_approval` with an intent and gets a handle and a receipt.
   The manager parses the intent once, finds the signer that offers the account, and for a
   Bitcoin request reads the PSBT against the wallet's xpub. A request it would not sign is
   refused here, before anything is shown.
2. The approver (the signer app, `evm_signer_ui`) calls `pending` and `acknowledge`. It gets
   the manager's own lines, the requester's claim apart from them, the commitment to echo
   back, the signer's name, and what that signer collects: a password, a PIN, or nothing.
3. The person approves. `approve` re-derives the commitment and checks the echo. It then
   computes one digest per item and calls the signer's `sign`, passing the password only
   when one was typed:
   - EIP-155 or EIP-1559 transaction hashes, EIP-191 and EIP-712 digests, or an opaque digest
     for EVM;
   - BIP143 or BIP341 sighashes for each input of a PSBT.
4. The signer answers with signatures only. The manager checks each one before building the
   result:
   - an EVM signature must recover to the account;
   - an ECDSA or BIP340 signature must verify against the key at that input's path, derived
     from the account's xpub.

   It then builds the result itself: the signed transaction envelope, the 65-byte signature,
   or the PSBT with signatures added. A wrong password leaves the request on screen.
5. The requester collects the results with its receipt.

A signer with a device answers `sign` with a job that waits for the person. The record then
stays in `signing`, and each later call checks how the job stands:
- a confirmation settles it `approved`;
- a refusal on the device settles it `rejected`;
- a failure puts it back on screen with the reason.

## Roles and tiers

| Tier | Methods | Admits |
|---|---|---|
| A | `pending`, `acknowledge`, `approve`, `reject` | a configured **approver** (default `evm_signer_ui`) |
| B | `request_approval`, `approval_status`, `fetch_result`, `ack_result`, `cancel_approval` | any **named module**; all but the first also need the receipt |
| C | `accounts`, `signers`, `caller_identity`, and for now `configure` | anyone |

Refusals are the identical `{"ok":false,"error":"not authorized"}`. The host anchor (the CLI)
is never a named module.

### `configure(config_json: String) -> String`

`{ approvers?, custodians?, signers? }` → `{ ok, approvers, custodians, signers }`. Total, as the
keystore's: a role or list the document doesn't name is held by nobody, and a malformed document
changes nothing. `signers` lists the signer modules consulted, in order; when two offer the same
account, the first holds it. Defaults: approver `evm_signer_ui`, custodian `evm_keystore_ui`
(for the open and unlock requests to come), signers `keystore_module`. It is ungated for now, like
the keystore's, and the keystore's caveat applies: the protection is deferred to module identity
in the core. A module that names itself a signer can refuse or stall a request, but it can't get a
false signature past the checks above.

## API

| Method | Params | Returns |
|---|---|---|
| `configure` | `config_json` | `{ ok, approvers, custodians, signers }` |
| `request_approval` | `intent_json` | `{ ok, handle, receipt, state }` |
| `approval_status` | `handle, receipt` | `{ ok, state, reason? }`; `state` is `offered`, `rendered`, `signing` or `settled` |
| `fetch_result` | `handle, receipt` | `{ ok, signed: [..] }`, idempotent until `ack_result` |
| `ack_result` | `handle, receipt` | `bool` |
| `cancel_approval` | `handle, receipt` | `bool`; a signer still working is told to stop |
| `pending` | — | `{ ok, pending: [{ handle, requester, state, purpose, legs, ageMs, error? }] }` |
| `acknowledge` | `handle` | `{ ok, handle, bundle_id, requester, claim_lines, render_lines, signer, collects }` |
| `approve` | `handle, bundle_id, password` | `{ ok, signed }`, or `{ ok, state: "signing" }`, or `{ ok: false, code, error }` |
| `reject` | `handle` | `bool` |
| `accounts` | — | `{ ok, accounts: [{ id, family, chain?, address?, label?, signer, available }] }` |
| `signers` | — | `{ ok, signers: [{ name, info? }] }` |
| `caller_identity` | — | `{ ok, kind, identity, approvers, custodians }` |

`approve`'s `code` is the signer's: `wrong_secret` (ask again), `locked` (no password and no
unlock), `unavailable` (the signer module didn't answer). `accounts` carries no xpub: a Bitcoin
wallet's xpub shows its whole history, so the manager does not hand it to whoever asks.

### The intent

Unchanged from `keystore_module`: `{ address | group, purpose?, legs }`, with legs `tx`
(`chain_id`, `tx`: the keystore's unsigned-transaction JSON), `message` (`text`), `digest`
(`digest`, `purpose`), `typed_data` (`typed_data`) and `psbt` (`network`, `psbt`, base64). An EVM
request names `address`; a Bitcoin request names `group` and carries exactly one `psbt` leg. The
render, the commitment rules and the refusals (displayable text only, declared EIP-712 fields only,
64 KiB, four pending per requester and sixteen in all, a sixty-second sweep for offers nobody
claimed) are the keystore's. The commitment's domain tag is now `logos-signer-manager-approval-v1`.

### A PSBT

Read as keystore_module's spike K0 read it:
- **Refused before anything is shown:**
  - an input this wallet can't sign, or one already signed;
  - a script path;
  - a native segwit input without its previous transaction, or with an amount that disagrees
    with it;
  - a sighash other than ALL, or DEFAULT for taproot;
  - a coin spent twice;
  - a network mismatch.
- **Change** is checked by deriving the key at the path the output claims.
- **The fee** is the manager's own sum.

The manager computes each input's sighash and hands the sighashes to the signer with each
input's path. It adds a signature to the PSBT only after the signature verifies. One signature
missing, or one that fails, adds none.

### Events

`approval_offered(handle)`, `approval_settled(handle, state)`, `approval_progress(handle, state)`
when a request moves to `signing`, and `accounts_changed(count)` after a signer reports its
accounts changed. Handles only: the event plane is unauthenticated.

## The signers

Signer modules are bound at runtime through the `signer` interface dependency
(`signer.lidl`, from `logos-signer-interface`), one binding per configured name. `keystore_module`
is also a concrete dependency, so it loads with the manager. A signer that doesn't answer within
three seconds for `signer_info`, or twenty for anything else, offers nothing until asked again.

## Build and test

```sh
cd rust-lib && cargo test --no-default-features   # the core, against the interface's mock signer
nix build                                         # the module
nix build '.#lgx'                                 # an installable package
./doctests/run.sh                                 # the round trip through logoscore
```
