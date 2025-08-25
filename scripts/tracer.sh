#!/bin/sh
SCRIPTS_DIR=$(dirname $(realpath $0))
NODE_DIR=$(pwd)
TMPFILE=$(mktemp tracerconfig.XXXXXXXXXX)
jq '.["network"].["contents"]="'${TMPFILE}'"' \
	< ${SCRIPTS_DIR}/tracerconfig-mainnet.sh.json > ${TMPFILE}
exec cabal --jobs=256 --keep-going --disable-documentation \
	run cardano-tracer:exe:cardano-tracer -- \
	-c ${TMPFILE}
