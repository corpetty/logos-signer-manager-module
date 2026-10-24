#!/usr/bin/env bash
# Identity keys end to end, headless, through a logoscore daemon: the keystore makes an Ed25519 key
# for a room from the phrase it holds, the manager shows a record, has the keystore sign it, checks
# the signature, and later signs one without asking inside an unlock. The signature is verified with
# libsodium, the library Muster verifies room events with.
#
#   doctests/identity-e2e.sh                  # the keystore from corpetty/logos-evm-keystore-module
#   KEYSTORE=path:/path/to/keystore doctests/identity-e2e.sh
#   KEEP=1 doctests/identity-e2e.sh           # keep the working directory and the daemon's log
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)
KEYSTORE="${KEYSTORE:-github:corpetty/logos-evm-keystore-module/1c819f220c9dd280a5f153296c57368efb866cc3}"
ABOUT="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# The reference derivation of m/7432'/0'/c0'…c7' for that phrase, purpose room-identity, context room:a.
WANT_PK=c8b57cf9c3cc450e042a6ce6f09b0664859d9a1dd916d75e16d76973b10afbba

W=$(mktemp -d); cd "$W"
fail() { echo "FAIL: $*"; echo "kept: $W"; tail -30 "$W/logs.txt" 2>/dev/null; exit 1; }
nb() { nix build "$@" --no-write-lock-file 2>"$W/build.err" || { tail -20 "$W/build.err"; fail "nix build $1"; }; }

echo "── build"
nb 'github:logos-co/logos-logoscore-cli/0.3.1#cli' -o logos
nb 'github:logos-co/logos-package-manager/3133786ea86821e251fccc82a2eefbfc4db7605e#cli' -o lgpm
nb "$KEYSTORE#lgx" -o keystore-lgx
nb "path:$REPO#lgx" -o manager-lgx
nb "path:$REPO?dir=doctests/manager-probe#lgx" --override-input signer_manager_module "path:$REPO" \
   --override-input keystore_module "$KEYSTORE" -o probe-lgx
mkdir -p modules && cp -RL ./logos/modules/. ./modules/ && chmod -R u+w modules
for x in keystore manager probe; do
  ./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file $x-lgx/*.lgx >/dev/null || fail "install $x"
done

L=./logos/bin/logoscore
lc() { timeout 60 $L --config-dir "$W/cfg" "$@" 2>&1 | tail -1; }
# A call's result, parsed: the CLI wraps the module's JSON string in {"result": "..."}.
res() { python3 -c 'import sys,json
r=json.loads(sys.stdin.read())
v=r.get("result",r)
print(v if isinstance(v,str) else json.dumps(v))'; }
call() { lc call "$@" | res; }
field() { python3 -c "import sys,json; v=json.loads(sys.stdin.read()); print(v$1)"; }

setsid $L --config-dir "$W/cfg" daemon -m ./modules --persistence-path "$W/data" > logs.txt 2>&1 &
DPID=$!
trap '[ -n "${KEEP:-}" ] || { lc stop >/dev/null; kill -9 -$DPID 2>/dev/null; rm -rf "$W"; }' EXIT
for _ in $(seq 1 20); do lc status >/dev/null && break; sleep 1; done

echo "── load and name the roles"
lc load-module manager_probe | grep -q '"status":"ok"' || fail "load manager_probe"
call keystore_module configure '{"approvers":"evm_signer_ui","custodians":"manager_probe","managers":"signer_manager_module"}' >/dev/null
call signer_manager_module configure '{"approvers":"manager_probe","custodians":"manager_probe","signers":"keystore_module"}' >/dev/null
call signer_manager_module signers | grep -q '"ed25519"' || fail "the keystore does not offer ed25519"

echo "── an identity group from the phrase, and the room's key"
g=$(call manager_probe import_identity "{\"phrase\":\"$ABOUT\",\"password\":\"pw\"}")
echo "  $g"; echo "$g" | grep -q '"fingerprint":"73c5da0a"' || fail "import_identity"
k=$(call manager_probe derive_identity '{"purpose":"room-identity","context":"room:a","password":"pw"}')
echo "  $k"
PK=$(echo "$k" | field '["publicKey"]'); KR=$(echo "$k" | field '["account"]')
[ "$PK" = "$WANT_PK" ] || fail "the room key is $PK, not the reference $WANT_PK"
call signer_manager_module accounts | grep -q "$PK" || fail "the manager does not list the identity key"

# Muster's authorship record, ["muster.event.author.v1", {room, author, seq}], in dCBOR.
record() { python3 - "$1" <<'PY'
import sys
def h(m,n):
    if n<24: return bytes([m<<5|n])
    if n<256: return bytes([m<<5|24,n])
    return bytes([m<<5|25])+n.to_bytes(2,'big')
def t(s): b=s.encode(); return h(3,len(b))+b
def u(n): return h(0,n)
pairs=sorted([(t("room"),t("room:a")),(t("author"),t("m1")),(t("seq"),u(int(sys.argv[1])))])
print((h(4,2)+t("muster.event.author.v1")+h(5,len(pairs))+b"".join(k+v for k,v in pairs)).hex())
PY
}
# Ed25519 over SHA-256 of the record, verified by libsodium's crypto_sign_verify_detached.
verify() { python3 - "$1" "$2" "$3" <<'PY'
import sys,ctypes,ctypes.util,hashlib
so=ctypes.CDLL(ctypes.util.find_library("sodium") or "libsodium.so.23"); assert so.sodium_init()>=0
pk,rec,sig=(bytes.fromhex(x) for x in sys.argv[1:4]); m=hashlib.sha256(rec).digest()
ok=so.crypto_sign_verify_detached(sig,m,ctypes.c_ulonglong(len(m)),pk)==0
print("libsodium verifies it" if ok else "libsodium REFUSES it"); sys.exit(0 if ok else 1)
PY
}

echo "── the CLI cannot ask"
call signer_manager_module request_approval "{\"identity\":\"$PK\",\"legs\":[]}" | grep -q "not authorized" || fail "the CLI asked"

echo "── a record, shown, approved, checked"
R3=$(record 3)
r=$(call manager_probe request "{\"identity\":\"$PK\",\"purpose\":\"post a message\",\"legs\":[{\"kind\":\"record\",\"record\":\"$R3\"}]}")
H=$(echo "$r" | field '["handle"]'); C=$(echo "$r" | field '["receipt"]')
shown=$(call manager_probe acknowledge "$H")
for want in "Identity key: $PK" "Domain: muster.event.author.v1" 'room: \"room:a\"' "seq: 3" '"collects":"password"' '"signer":"keystore_module"'; do
  echo "$shown" | grep -qF "$want" || fail "the approver was not shown: $want"
done
echo "$shown" | field '["render_lines"]' | python3 -c 'import sys,ast; [print("   ",l) for l in ast.literal_eval(sys.stdin.read())]'
B=$(echo "$shown" | field '["bundle_id"]')
call manager_probe approve "$H" "$B" wrong | grep -q '"code":"wrong_secret"' || fail "a wrong password"
call manager_probe status "$H" "$C" | grep -q '"state":"rendered"' || fail "still on screen after a wrong password"
call manager_probe approve "$H" "$B" pw | grep -q '"signed_count":1' || fail "approve"
SIG=$(call manager_probe fetch "$H" "$C" | field '["signed"][0]')
echo "  signature $SIG"; verify "$PK" "$R3" "$SIG" || fail "signature"

echo "── refused before anything is shown"
BAD=826164a262616101616202   # ["d", {"aa":1, "b":2}]: keys out of bytewise order
call manager_probe request "{\"identity\":\"$PK\",\"legs\":[{\"kind\":\"record\",\"record\":\"$BAD\"}]}" | grep -q '"ok":false' || fail "a non-canonical record"
call manager_probe request "{\"identity\":\"$PK\",\"legs\":[{\"kind\":\"digest\",\"digest\":\"0x$(printf '11%.0s' $(seq 32))\",\"purpose\":\"x\"}]}" | grep -q '"ok":false' || fail "a digest for an identity"
call manager_probe sign_direct "{\"account\":\"$KR\",\"kind\":\"hash\",\"items\":[{\"scheme\":\"ed25519\",\"digest\":\"$(printf '22%.0s' $(seq 32))\"}],\"secret\":\"pw\"}" | grep -q "not authorized" || fail "the keystore signed past the manager"

echo "── without asking, inside an unlock the person granted"
u=$(call manager_probe unlock "{\"account\":\"$KR\",\"password\":\"pw\",\"count\":5,\"apps\":[\"manager_probe\"],\"confirm\":false}")
echo "  $u"; echo "$u" | grep -q '"countLeft":5' || fail "unlock"
R4=$(record 4)
r=$(call manager_probe request "{\"identity\":\"$PK\",\"purpose\":\"post a message\",\"legs\":[{\"kind\":\"record\",\"record\":\"$R4\"}]}")
echo "$r" | grep -q '"state":"settled"' || fail "not signed as it arrived: $r"
SIG=$(call manager_probe fetch "$(echo "$r" | field '["handle"]')" "$(echo "$r" | field '["receipt"]')" | field '["signed"][0]')
verify "$PK" "$R4" "$SIG" || fail "unattended signature"

echo "PASS: an identity key from the kept phrase signs a Muster record through the manager, shown or within an unlock"
