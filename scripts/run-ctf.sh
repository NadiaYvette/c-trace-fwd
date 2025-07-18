#!/bin/sh
SOCK_FILE=$(realpath ../tracer-repl-mod/mainnetsingle/socket/tracer.socket)
exec env LD_PRELOAD=./obj/lib/libc_trace_fwd.so \
	LD_LIBRARY_PATH=$(pwd)/obj/lib:/lib:/usr/lib \
	valgrind --tool=memcheck \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		./obj/bin/c_trace_fwd \
			-f $SOCK_FILE \
			-q ./logs/handshake.log.007.A \
			-u 127.0.0.1:9001
