#include <cbor.h>
#include "datapoint.h"

cbor_item_t *
build_empty_metrics_resp(void)
{
	cbor_item_t *arr, *tag, *val;

	if (!(arr = cbor_new_definite_array(2)))
		return NULL;
	if (!(tag = cbor_build_uint8(datapoint_resp)))
		goto out_decref_arr;
	if (!cbor_array_set(arr, 0, tag))
		goto out_decref_tag;
	if (!(val = cbor_new_definite_array(0)))
		goto out_decref_tag;
	if (!cbor_array_set(arr, 1, val))
		goto out_decref_val;
	return arr;
out_decref_val:
	cbor_decref(&val);
out_decref_tag:
	cbor_decref(&tag);
out_decref_arr:
	cbor_decref(&arr);
	return NULL;
}
