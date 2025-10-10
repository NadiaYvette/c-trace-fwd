#pragma once

#include <cbor.h>
#include "datapoint.h"
#include "handshake.h"
#include "metrics.h"
#include "tof.h"

union msg {
	cbor_item_t undecoded;
	struct datapoint_msg datapoint_msg;
	struct handshake handshake_msg;
	struct metrics_msg metrics_msg;
	struct tof_msg tof_msg;
};
