#!/bin/sh
SCRIPTS_DIR=$(dirname $(realpath $0))
# echo SCRIPTS_DIR=${SCRIPTS_DIR}
NODE_DIR=${NODE_DIR:-$(realpath $(pwd))}
# echo NODE_DIR=${NODE_DIR}
NODE_MAINNET_DIR=${NODE_MAINNET_DIR:-${NODE_DIR}/mainnetsingle}
# echo NODE_MAINNET_DIR=${NODE_MAINNET_DIR}
NODE_SOCKET_DIR=${NODE_SOCKET_DIR:-${NODE_MAINNET_DIR}/socket}
# NODE_SOCKET_DIR=${NODE_SOCKET_DIR:-${NODE_DIR}/run/current/tracer}
# echo NODE_SOCKET_DIR=${NODE_SOCKET_DIR}
if [ ! -d "${NODE_SOCKET_DIR}" ]
then
	echo Creating NODE_SOCKET_DIR=${NODE_SOCKET_DIR}
	mkdir -p ${NODE_SOCKET_DIR}
fi
NODE_TRACER_SOCK=$(realpath ${NODE_SOCKET_DIR}/tracer.socket)
# echo NODE_TRACER_SOCK=${NODE_TRACER_SOCK}
TMPFILE=/tmp/$(mktemp tracerconfig.XXXXXXXXXX)
# echo TMPFILE=${TMPFILE}
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
