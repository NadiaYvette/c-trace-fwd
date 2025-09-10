#!/bin/sh
NODE_DIR=${NODE_DIR:-../cardano-node}
NODE_SOCK_DIR=${NODE_SOCK_DIR:-${NODE_DIR}/mainnetsingle/socket}
# NODE_SOCK_DIR=${NODE_SOCK_DIR:-$(realpath ${NODE_DIR}/run/current/tracer)}
SOCK_FILE=${SOCK_FILE:-$(realpath ${NODE_SOCK_DIR}/tracer.socket)}
if [ -v DEBUG ]
then
	echo NODE_DIR=${NODE_DIR}
	echo NODE_SOCK_DIR=${NODE_SOCK_DIR}
	echo SOCK_FILE=$(realpath ${SOCK_FILE})
	sleep 10
fi
exec env LD_PRELOAD=./obj/lib/libc_trace_fwd.so \
	LD_LIBRARY_PATH=$(pwd)/obj/lib:/lib:/usr/lib \
	valgrind --tool=memcheck \
		--leak-check=full \
		--show-leak-kinds=all \
		--show-error-list=all \
		--track-origins=yes \
		./obj/bin/c_trace_fwd \
			-f ${SOCK_FILE} \
			-q ./logs/handshake.log.007.A \
			-u 127.0.0.1:9001
