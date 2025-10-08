=========
  BUILD
=========

        $ make -j all

Static checking reliant on clang-check can be done via
        $ make check
beyond just building.

If you really want to build absolutely nothing but the executable or
nothing but the library,

        $ make -j $(pwd)/obj/bin/c_trace_fwd
                and
        $ make -j $(pwd)/obj/bin/libc_trace_fwd.so

can be done, though it's a bit of an artifact of the way non-recursive
make with separate output directories was done that the absolute path is
required.


========
  TEST
========

The ./scripts/ directory mostly wraps up command-line options around
different things to invoke. Using the left half of a 24x80 terminal
for the trace forwarding library and the right half for the Haskell trace
forwarder,

        ~/src/c-trace-fwd/          |          ~/src/cardano-node
    ===========================     |       ========================
                                    |  $ make ci-test
                                    |  $ ../c-trace-fwd/scripts/tracer.sh
                                    |
                     (wait for tracer to build and start)
                                    |
$ ./scripts/run-ctf.sh


In principle, in a third terminal, one could launch in ~/src/cardano-node/
via
$ make ci-test
$ ../c-trace-fwd/node.sh
to have a node generate traffic for the tracer.
The c_trace_fwd executable depends on libc_trace_fwd.so which
./scripts/run-ctf.sh loads as an LD_PRELOAD but in a full system
installation should be picked up in an LD_LIBRARY_PATH as usual.
The run-ctf.sh script also runs the executable under valgrind.

The executables for other tests and the library, when built, are built
by default in ./obj/bin and ./obj/lib

========================
  COMMAND-LINE OPTIONS
========================

c_trace_fwd accepts the options:

  -f FILE
        The Unix-domain socket file used for communication with the
        upstream tracer.
  -q FILE
        A log of messages to preload a queue of messages to be sent
        with.
  -t
        Run in threaded mode.
  -u IP_ADDR:PORT_NUM
        An IP address and port number to forward the trace messages to
        (while needed so start-up doesn't fail, it's not used).
  -v VERBOSITY_LEVEL
       The minimum verbosity level required for messages. This should
       probably be numerically inverted so as to align with the ways
       verbosity levels are more typically arranged for verbosity level
       options (and maybe also allow descriptive log level names).
