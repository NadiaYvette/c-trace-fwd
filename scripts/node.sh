#!/bin/sh

CTF_SCRIPTS_DIR=$(dirname $(realpath $0))
CTF_MAINNET_DIR=${CTF_SCRIPTS_DIR}
CTF_CARDANO_DIR=${CTF_SCRIPTS_DIR}

NODE_SCRIPTS_DIR=$(realpath $(pwd))
NODE_EMPTY_DIR=${NODE_SCRIPTS_DIR}/empty_dir
NODE_MAINNET_DIR=${NODE_SCRIPTS_DIR}/mainnetsingle
NODE_CARDANO_DIR=${NODE_SCRIPTS_DIR}/cardano
NODE_CONFIG_DIR=${NODE_SCRIPTS_DIR}/configuration

NODE_ALONZO_GENESIS=${NODE_CONFIG_DIR}/cardano/mainnet-alonzo-genesis.json
NODE_BYRON_GENESIS=${NODE_CONFIG_DIR}/cardano/mainnet-byron-genesis.json
NODE_SHELLEY_GENESIS=${NODE_CONFIG_DIR}/cardano/mainnet-shelley-genesis.json
NODE_CONWAY_GENESIS=${NODE_CONFIG_DIR}/cardano/mainnet-conway-genesis.json

echo NODE_ALONZO_GENESIS=${NODE_ALONZO_GENESIS}
echo NODE_BYRON_GENESIS=${NODE_BYRON_GENESIS}
echo NODE_SHELLEY_GENESIS=${NODE_SHELLEY_GENESIS}
echo NODE_CONWAY_GENESIS=${NODE_CONWAY_GENESIS}

CONFIG_JSON=${CTF_CARDANO_DIR}/mainnet-config-new-tracing.json
NODE_DB_PATH=${NODE_MAINNET_DIR}/db
NODE_DB_SOCK=${NODE_DB_PATH}/node.socket
TOPOLOGY_JSON=${CTF_CARDANO_DIR}/mainnet-topology.json
TRACER_SOCK=${NODE_MAINNET_DIR}/socket/tracer.socket

TMPFILE=/tmp/$(mktemp nodeconfig.XXXXXXXXXX)
echo TMPFILE=${TMPFILE}
JQ_ALONZO_CMD='.["AlonzoGenesisFile"]="'${NODE_ALONZO_GENESIS}'"'
JQ_BYRON_CMD='.["ByronGenesisFile"]="'${NODE_BYRON_GENESIS}'"'
JQ_SHELLEY_CMD='.["ShelleyGenesisFile"]="'${NODE_SHELLEY_GENESIS}'"'
JQ_CONWAY_CMD='.["ConwayGenesisFile"]="'${NODE_CONWAY_GENESIS}'"'

echo JQ_ALONZO_CMD=${JQ_ALONZO_CMD}
echo JQ_BYRON_CMD=${JQ_BYRON_CMD}
echo JQ_SHELLEY_CMD=${JQ_SHELLEY_CMD}
echo JQ_CONWAY_CMD=${JQ_CONWAY_CMD}

JQ_CMD=${JQ_ALONZO_CMD}' | '${JQ_BYRON_CMD}' | '${JQ_SHELLEY_CMD}' | '${JQ_CONWAY_CMD}
echo JQ_CMD=${JQ_CMD}

# jq ${JQ_ALONZO_CMD}' | '${JQ_BYRON_CMD}' | '${JQ_CONWAY_CMD} \

jq "${JQ_CMD}" < ${CONFIG_JSON} > ${TMPFILE}
exec cabal --jobs=256 --keep-going --disable-documentation run cardano-node -- \
	run --config ${TMPFILE} \
		--database-path ${NODE_DB_PATH} \
		--socket-path ${NODE_DB_SOCK} \
		--host-addr 0.0.0.0 \
		--port 3001 \
		--topology ${TOPOLOGY_JSON} \
		--tracer-socket-path-connect ${TRACER_SOCK}
