#!/bin/sh
exec cabal --jobs=256 run cardano-node -- \
	run --config ./configuration/cardano/mainnet-config-new-tracing.json \
		--database-path ./mainnetsingle/db \
		--socket-path ./mainnetsingle/db/node.socket \
		--host-addr 0.0.0.0 \
		--port 3001 \
		--topology ./configuration/cardano/mainnet-topology.json \
		--tracer-socket-path-connect \
			./mainnetsingle/socket/tracer.socket
