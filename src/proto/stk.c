#include <cbor.h>
#include <time.h>
#include "c_trace_fwd.h"
#include "sdu.h"
#include "tof.h"

struct tof_msg *
ctf_proto_stk_decode(const void *buf)
{
	struct sdu sdu;
	struct cbor_load_result cbor_load_result;
	cbor_item_t *tof_cbor;
	const uint32_t *hdr = (uint32_t *)buf;

	if (sdu_decode(hdr, &sdu))
		return NULL;
	sdu.sdu_data = (const char *)&hdr[2];
	tof_cbor = cbor_load((cbor_data)sdu.sdu_data, sdu.sdu_len, &cbor_load_result);
	if (!tof_cbor)
		return NULL;
	return tof_decode(tof_cbor);
}

char *
ctf_proto_stk_encode(const struct tof_msg *msg, size_t *ret_sz)
{
	char *buf;
	size_t buf_sz, cbor_sz;
	cbor_item_t *tof_cbor;
	struct sdu sdu;

	if (!(tof_cbor = tof_encode(msg)))
		return NULL;
	if (!(cbor_sz = cbor_serialized_size(tof_cbor)))
		goto exit_free_cbor;
	buf_sz = cbor_sz + 2*sizeof(uint32_t);
	if (!(buf = calloc(1, buf_sz)))
		goto exit_free_cbor;
	if (!cbor_serialize(tof_cbor, (unsigned char *)&buf[2*sizeof(uint32_t)], cbor_sz))
		goto exit_free_buf;
	sdu.sdu_xmit = time(NULL);
	/* 0 is used everywhere I can find */
	sdu.sdu_proto_num = 0;
	/* false = initiator, true = responder */
	sdu.sdu_init_or_resp = false;
	sdu.sdu_len = buf_sz;
	sdu.sdu_data = buf;
	*ret_sz = buf_sz;
	if (sdu_encode(&sdu, (uint32_t *)buf))
		goto exit_free_buf;
	cbor_decref(&tof_cbor);
	return buf;
exit_free_buf:
	free(buf);
exit_free_cbor:
	cbor_decref(&tof_cbor);
	return NULL;
}
