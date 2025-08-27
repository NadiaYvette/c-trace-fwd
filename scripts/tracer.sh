#!/bin/sh
SCRIPTS_DIR=$(dirname $(realpath $0))
NODE_DIR=$(realpath $(pwd))
NODE_MAINNET_DIR=${NODE_DIR}/mainnnetsingle
NODE_SOCKET_DIR=${NODE_MAINNET_DIR}/socket
NODE_TRACER_SOCK=${NODE_SOCKET_DIR}/tracer.socket
TMPFILE=$(mktemp tracerconfig.XXXXXXXXXX)
jq '.["network"].["contents"]="'${NODE_TRACER_SOCK}'"' \
	< ${SCRIPTS_DIR}/tracerconfig-mainnet.sh.json > ${TMPFILE}
exec cabal --jobs=256 --keep-going --disable-documentation \
	run cardano-tracer:exe:cardano-tracer -- \
	-c ${TMPFILE}
