#! /usr/bin/env nix-shell
#! nix-shell -i bash -p bash

N="$1"
DATADIR="$2"

if [[ -z "$N" || -z "$DATADIR" ]]; then
  echo "usage: $0 <N> <datadir>"
  exit 1
fi

mkdir -p "$DATADIR"
if [[ "$(ls -A "$DATADIR")" ]]; then
  echo "error: $DATADIR is not empty"
  exit 1
fi

for i in $(seq 0 $((N-1))); do
  docker run \
    -d \
    --name node-$i \
    --hostname node-$i \
    -v "$DATADIR":/data \
    -e NODES="$N" \
    -e MSGRATE=10 \
    -e MSGSIZE=20 \
    -e PUBLISHERS=5 \
    -e CONNECTTO=4 \
    -e LOG_LEVEL=TRACE \
    --entrypoint /node/main \
    mixrunner
done
