#!/bin/sh
exec env LD_PRELOAD=./obj/lib/libc_trace_fwd.so LD_LIBRARY_PATH=$(pwd)/obj/lib:/lib:/usr/lib valgrind --tool=memcheck --leak-check=full --track-origins=yes ./obj/bin/c_trace_fwd -f $(realpath ../tracer-repl-mod/mainnetsingle/socket/tracer.socket) -u 127.0.0.1:9001
