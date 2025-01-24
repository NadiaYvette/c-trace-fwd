#pragma once

#include <cbor.h>
#include "tof.h"

struct tof_msg *ctf_proto_stk_decode(const void *);
void *ctf_proto_stk_encode(const struct tof_msg *, size_t *);
