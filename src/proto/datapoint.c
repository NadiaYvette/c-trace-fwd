#include <cbor.h>
#include "datapoint.h"

cbor_item_t *
build_empty_datapoint_resp(void)
{
	cbor_item_t *arr, *val;

	if (!(arr = cbor_new_definite_array(1)))
		return NULL;
	if (!(val = cbor_build_uint8(datapoint_resp)))
		goto out_decref_arr;
	if (!cbor_array_set(arr, 0, val))
		goto out_decref_val;
	return arr;
out_decref_val:
	cbor_decref(&val);
out_decref_arr:
	cbor_decref(&arr);
	return NULL;
}
