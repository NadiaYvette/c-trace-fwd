#include <cbor.h>
#include <time.h>
#include "c_trace_fwd.h"
#include "sdu.h"
#include "tof.h"

struct tof_msg *
ctf_proto_stk_decode(const char *buf)
{
	struct sdu sdu;
	struct cbor_load_result cbor_load_result;
	cbor_item_t *tof_cbor;
	uint32_t *hdr = (uint32_t *)buf;

	if (sdu_decode(hdr, &sdu))
		return NULL;
	sdu.sdu_data = &buf[2 * sizeof(uint32_t)];
	tof_cbor = cbor_load((cbor_data)sdu.sdu_data, sdu.sdu_len, &cbor_load_result);
	if (!tof_cbor)
		return NULL;
	return tof_decode(tof_cbor);
}

char *
ctf_proto_stk_encode(const struct tof_msg *msg)
{
	char *buf, *ret;
	size_t buf_sz;
	cbor_item_t *tof_cbor;
	struct sdu sdu;

	tof_cbor = tof_encode(msg);
	if (!cbor_serialize_alloc(tof_cbor, (unsigned char **)&buf, &buf_sz))
		return NULL;
	sdu.sdu_xmit = time(NULL);
	/* 0 is used everywhere I can find */
	sdu.sdu_proto_num = 0;
	/* false = initiator, true = responder */
	sdu.sdu_init_or_resp = false;
	sdu.sdu_len = buf_sz;
	sdu.sdu_data = buf;
	if (!(ret = malloc(buf_sz + 2 * sizeof(uint32_t))))
		return NULL;
	if (sdu_encode(&sdu, (uint32_t *)&ret[2 * sizeof(uint32_t)]))
		return NULL;
	memcpy(&ret[2 * sizeof(uint32_t)], buf, buf_sz);
	return ret;
}
