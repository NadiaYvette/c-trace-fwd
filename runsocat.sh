NODE_GIT_DIR=${NODE_GIT_DIR:-${PWD}}

# The TRACE_DIR directory is depended on by the script maintained in
# git at ${NODE_GIT_DIR}/scripts/lite/mainnet-new-tracing.sh
TRACE_DIR=${TRACE_DIR:-${NODE_GIT_DIR}/mainnetsingle}

# Unix domain sockets are mildly awkward to create from shell scripts;
# however, the socat(1) utility among others will do it as a by-product
# of bind(2)/connect(2) operations with the ->sun_path[] component of
# the struct sockaddr_un (always casted to the never-defined but
# forward-declared struct sockaddr)
SOCK_DIR=${SOCK_DIR:-${TRACE_DIR}/socket}
SOCK_FILE=${SOCK_FILE:-${SOCK_DIR}/tracer.socket}

# The verbatim writing of this was:
# mv mainnetsingle/socket/tracer.socket mainnetsingle/socket/tracer.socket.orig
mv ${SOCK_FILE} ${SOCK_FILE}.orig

# -v tees data written to targets to stderr, prefixing lines with flow
#        direction markers < and > and some conversions for readability.
# -x also tees data written to targets to stderr, largely identically to
#        the same way -v does, but with hex formatting.
# -t${TIMEOUT} gives TIMEOUT seconds to a half-closed connection
#        (received EOF but only on one end) perhaps for it to recover.
#        Receiving EOF on the other end will trigger an immediate exit.
TIMEOUT=${TIMEOUT:-100}
SOCAT_OPT=${SOCAT_OPT:-"-t${TIMEOUT} -v -x"}

# For want of specified nomenclature, the first socket/file/fd argument
# is what this script will call the "front," and the second, the "back."
# These aren't likely to be worthwhile to override.
FRONT_ADDR_TYPE=${FRONT_ADDR_TYPE:-"UNIX-LISTEN"}
BACK__ADDR_TYPE=${BACK__ADDR_TYPE:-"UNIX-CONNECT"}

# Maybe someone might want to overridde it.
SOCAT=${SOCAT:-$(which socat)}
exec ${SOCAT} ${SOCAT_OPT} \
  ${FRONT_ADDR_TYPE}:${SOCK_FILE},mode=777,reuseaddr,fork \
  ${BACK__ADDR_TYPE}:${SOCK_FILE}.orig
