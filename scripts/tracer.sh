#!/bin/sh
SCRIPTS_DIR=$(dirname $(realpath $0))
NODE_DIR=${NODE_DIR:-$(realpath $(pwd))}
NODE_MAINNET_DIR=${NODE_MAINNET_DIR:-${NODE_DIR}/mainnetsingle}
NODE_SOCKET_DIR=${NODE_SOCKET_DIR:-${NODE_MAINNET_DIR}/socket}
# NODE_SOCKET_DIR=${NODE_SOCKET_DIR:-${NODE_DIR}/run/current/tracer}
NODE_TRACER_SOCK=$(realpath ${NODE_SOCKET_DIR}/tracer.socket)
TMPFILE=/tmp/$(mktemp tracerconfig.XXXXXXXXXX)
if [ -v DEBUG ]
then
	echo NODE_TRACER_SOCK=${NODE_TRACER_SOCK}
	echo TMPFILE=${TMPFILE}
fi
jq '.["network"].["contents"]="'${NODE_TRACER_SOCK}'"' \
	< ${SCRIPTS_DIR}/tracerconfig-mainnet.sh.json > ${TMPFILE}
exec cabal --jobs=256 --keep-going --disable-documentation \
	run cardano-tracer:exe:cardano-tracer -- \
	-c ${TMPFILE}
