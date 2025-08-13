#!/bin/sh
SOCK_FILE=$(realpath ../tracer-repl-mod/mainnetsingle/socket/tracer.socket)
exec env LD_PRELOAD=./obj/lib/libc_trace_fwd.so \
	LD_LIBRARY_PATH=$(pwd)/obj/lib:/lib:/usr/lib \
	valgrind --tool=memcheck \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		./obj/bin/empty_loop \
			-u $SOCK_FILE
