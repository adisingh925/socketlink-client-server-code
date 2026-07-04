#!/usr/bin/env bash
# build_local.sh — build the optimized (current tree) and original (master) server
# in LOCAL_TEST mode for side-by-side testing.
#
# Requires the dependencies staged in $SL_DEPS (default: $HOME/sl-deps):
#   include/{httplib.h,json.hpp,simdjson.h}, simdjson.cpp,
#   uWebSockets/ (with uSockets/uSockets.a built via `WITH_OPENSSL=1 make`)
# and the apt dev libs: build-essential libssl-dev zlib1g-dev liblmdb-dev
#   libtbb-dev libboost-all-dev libmysqlclient-dev libbpf-dev
#
# Outputs: /tmp/sl_new (this branch) and /tmp/sl_orig (master baseline).
set -u
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
D="${SL_DEPS:-$HOME/sl-deps}"
SRC="$REPO/examples/SocketlinkClientServer.cpp"

INC="-I$D/uWebSockets/src -I$D/uWebSockets/uSockets/src -I$D/include -I/usr/include/mysql"
LIB="$D/uWebSockets/uSockets/uSockets.a -lssl -lcrypto -lz -llmdb -ltbb -lmysqlclient -lbpf -lpthread"
STD="-std=c++17 -O2"

echo "=== building /tmp/sl_new (current tree, -DLOCAL_TEST) ==="
g++ $STD -DLOCAL_TEST $INC "$SRC" "$D/simdjson.cpp" $LIB -o /tmp/sl_new
echo "new exit $?"

echo "=== building /tmp/sl_orig (master baseline, LOCAL_TEST bypass patched in) ==="
git -C "$REPO" show master:examples/SocketlinkClientServer.cpp > /tmp/orig_master.cpp
python3 "$SP/patch_orig.py"
g++ $STD $INC /tmp/orig_test.cpp "$D/simdjson.cpp" $LIB -o /tmp/sl_orig
echo "orig exit $?"

ls -la /tmp/sl_new /tmp/sl_orig
