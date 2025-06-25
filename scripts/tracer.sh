#!/bin/sh
exec cabal --jobs=256 --keep-going --disable-documentation \
	run cardano-tracer:exe:cardano-tracer -- \
	-c ./empty_dir/tracerconfig-mainnet.sh.json
