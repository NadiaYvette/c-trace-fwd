#!/bin/sh
exec lsof -a -U -u${USER} -c'/socat|cardano-(tracer|node)/' -c'/^discord/' +E
