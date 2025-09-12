#include <cbor.h>
#include <time.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "datapoint.h"
#include "metrics.h"
#include "proto_stk.h"
#include "sdu.h"
#include "tof.h"

static void
cpsdr_release_memory(void *p)
{
	struct ctf_proto_stk_decode_result *cpsdr = p;

	if (cpsdr->load_result.error.code != CBOR_ERR_NONE)
		return;
	if (cpsdr->sdu.sdu_proto_un.sdu_proto_num == mpn_trace_objects) {
		if (cpsdr->proto_stk_decode_result_body.tof_msg != NULL) {
			tof_free(cpsdr->proto_stk_decode_result_body.tof_msg);
			cpsdr->proto_stk_decode_result_body.tof_msg = NULL;
		}
	} else if (cpsdr->proto_stk_decode_result_body.undecoded != NULL) {
		cbor_decref(&cpsdr->proto_stk_decode_result_body.undecoded);
		cpsdr->proto_stk_decode_result_body.undecoded = NULL;
	}
}

void
cpsdr_free(struct ctf_proto_stk_decode_result *cpsdr)
{
	g_rc_box_release_full(cpsdr, cpsdr_release_memory);
}

struct ctf_proto_stk_decode_result *
ctf_proto_stk_decode(int fd)
{
	char *cur_buf, *buf;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct cbor_load_result *load_result_addr;
	cbor_item_t *tof_cbor;
	struct sdu sdu;
	const union sdu_ptr hdr = { .sdu8 = (uint8_t *)&sdu, };
	cbor_data sdu_data_addr;
	size_t sdu_data_len, sz, cur_sz;
	ssize_t ret_sz;
	unsigned retry_limit = 4 * 1024, retries = 0;

	ctf_msg(stk, "enter\n");
	if (!(cpsdr = g_rc_box_new0(struct ctf_proto_stk_decode_result))) {
		ctf_msg(stk, "g_rc_box_new0() failed\n");
		return NULL;
	}
	sz = 2*sizeof(uint32_t);
	cur_sz = sz;
	cur_buf = (char *)hdr.sdu8;
	ctf_msg(stk, "starting SDU IO loop\n");
	do {
		ctf_msg(stk, "read(%d, %p, %zu)\n", fd, cur_buf,
				cur_sz);
		ret_sz = read(fd, cur_buf, cur_sz);
		ctf_msg(stk, "read(%d, %p, %zu) = %zd\n", fd, cur_buf,
				cur_sz, ret_sz);
		if (ret_sz < 0) {
			ctf_msg(stk, "negative branch\n");
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ctf_msg(stk, "read() failure (%d): %s\n", errno,
					strerror(errno));
			goto out_free_cpsdr;
		} else if (!ret_sz) {
			ctf_msg(stk, "zero case retry %u\n", retries);
			if (++retries >= retry_limit) {
				ctf_msg(stk, "retry limit reached!\n");
				goto out_free_cpsdr;
			}
			(void)!sched_yield();
			continue;
		} else if (ret_sz < cur_sz) {
			ctf_msg(stk, "bounded above by cur_sz branch\n");
			cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
			cur_sz -= MIN(cur_sz, ret_sz);
			(void)!sched_yield();
			continue;
		} else {
			ctf_msg(stk, "ret_sz >= 0 && "
					"ret_sz >= cur_sz branch?\n");
			ctf_msg(stk, "ret_sz = %zd, cur_sz = %zu\n",
					ret_sz, cur_sz);
			assert(ret_sz == cur_sz);
			break;
		}
	} while (cur_sz > 0);
	ctf_msg(stk, "finished SDU IO loop\n");
	if (sdu_decode(hdr, &cpsdr->sdu) != RETVAL_SUCCESS) {
		ctf_msg(stk, "sdu_decode() failed\n");
		goto out_free_cpsdr;
	}
	ctf_msg(stk, "received SDU:\n");
	sdu_print(&cpsdr->sdu);
	cpsdr->sdu.sdu_data = (const char *)&hdr.sdu32[2];
	load_result_addr = &cpsdr->load_result;
	if (!(buf = g_rc_box_alloc0(65 * 1024))) {
		ctf_msg(stk, "buf calloc() failed\n");
		goto out_free_cpsdr;
	}
	(void)!memcpy(&buf[0], &sdu, 2*sizeof(uint32_t));
	cpsdr->sdu.sdu_data = &buf[2*sizeof(uint32_t)];
	sdu_data_addr = (cbor_data)cpsdr->sdu.sdu_data;
	sdu_data_len  = cpsdr->sdu.sdu_len;
	sz = sdu_data_len;
	cur_sz = sz;
	cur_buf = (char *)sdu_data_addr;
	ctf_msg(stk, "starting CBOR payload IO loop\n");
	do {
		ret_sz = read(fd, cur_buf, cur_sz);
		if (ret_sz < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			goto out_free_buf;
		} else if (ret_sz < cur_sz) {
			cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
			cur_sz -= MIN(cur_sz, ret_sz);
			(void)!sched_yield();
			continue;
		} else {
			assert(ret_sz == cur_sz);
			break;
		}
	} while (cur_sz > 0);
	ctf_msg(stk, "finished CBOR payload IO loop\n");
	ctf_msg(stk, "doing cbor_load() on payload\n");
	tof_cbor = cbor_load(sdu_data_addr, sdu_data_len, load_result_addr);
	ctf_msg(stk, "got past payload cbor_load()\n");
	ctf_msg(stk, "checking ->error.code\n");
	switch (load_result_addr->error.code) {
	case CBOR_ERR_NONE:
		break;
	case CBOR_ERR_NOTENOUGHDATA:
		ctf_msg(stk, "CBOR_NOTENOUGHDATA returned by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(stk, "tof_cbor != NULL (%p) despite "
					"CBOR_ERR_NOTENOUGHDATA?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		/* cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor; */
		return cpsdr;
	case CBOR_ERR_NODATA:
		ctf_msg(stk, "CBOR_ERR_NODATA returned by cbor_load(%zd)\n",
				sdu_data_len);
		sdu_print(&cpsdr->sdu);
		if (!!tof_cbor) {
			ctf_msg(stk, "tof_cbor != NULL (%p) despite "
					"CBOR_ERR_NODATA?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		/* cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor; */
		return cpsdr;
	case CBOR_ERR_MALFORMATED:
		ctf_msg(stk, "CBOR_ERR_MALFORMATED returned by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(stk, "tof_cbor != NULL (%p) despite "
					"CBOR_ERR_MALFORMATED?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		/* cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor; */
		return cpsdr;
	case CBOR_ERR_MEMERROR:
		ctf_msg(stk, "CBOR_ERR_MEMERROR returned by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(stk, "tof_cbor != NULL (%p) despite "
					"CBOR_ERR_MEMERROR?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		/* cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor; */
		return cpsdr;
	case CBOR_ERR_SYNTAXERROR:
		ctf_msg(stk, "CBOR_ERR_SYNTAXERROR returned by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(stk, "tof_cbor != NULL (%p) despite "
					"CBOR_ERR_SYNTAXERROR?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		/* cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor; */
		return cpsdr;
	default:
		ctf_msg(stk, "unrecognized error code %d returned"
			       " by cbor_load()\n",
			       load_result_addr->error.code);
		if (!!tof_cbor)
			ctf_msg(stk, "tof_cbor != NULL (%p) despite "
					"unrecognized error code?\n",
					tof_cbor);
		return cpsdr;
	}
	ctf_msg(stk, "got past ->error.code check\n");
	if (!tof_cbor) {
		ctf_msg(stk, "tof_cbor unexpectedly NULL\n");
		goto out_free_cpsdr;
	}
	ctf_msg(stk, "checking miniprotocol nr\n");
	switch (cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
	case mpn_handshake:
		cpsdr->proto_stk_decode_result_body.handshake_msg
			= handshake_decode(tof_cbor);
		if (!cpsdr->proto_stk_decode_result_body.handshake_msg) {
			ctf_msg(stk, "handshake_decode() failed\n");
			goto out_free_tof_cbor;
		}
		ctf_cbor_decref(stk, &tof_cbor);
		break;
	case mpn_trace_objects:
		if (!(cpsdr->proto_stk_decode_result_body.tof_msg = tof_decode(tof_cbor))) {
			ctf_msg(stk, "tof_decode() failed\n");
			goto out_free_tof_cbor;
		}
		/* This case translates the CBOR to C trace object data
		 * structures and discards the intermediate CBOR results. */
		ctf_cbor_decref(stk, &tof_cbor);
		break;
	case mpn_EKG_metrics:
		ctf_msg(stk, "mpn_EKG_metrics packet\n");
	case mpn_data_points:
		if (cpsdr->sdu.sdu_proto_un.sdu_proto_num == mpn_data_points)
			ctf_msg(stk, "mpn_EKG_metrics packet\n");
	default:
		/* These cases return the CBOR uninterpreted w/elevated
		 * refcount. Empty replies need to be sent to requests. */
		if (!MPN_VALID(cpsdr->sdu.sdu_proto_un.sdu_proto_num))
			ctf_msg(stk, "packet w/unhandled miniprotocol %d\n",
				(int)cpsdr->sdu.sdu_proto_un.sdu_proto_num);
		cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor;
		break;
	}
	ctf_msg(stk, "past miniprotocol nr check\n");
	ctf_msg(stk, "return %p\n", cpsdr);
	return cpsdr;
out_free_tof_cbor:
	ctf_msg(stk, "at out_free_tof_cbor label\n");
	if (!!tof_cbor)
		ctf_cbor_decref(stk, &tof_cbor);
out_free_buf:
	ctf_msg(stk, "at out_free_buf label\n");
	g_rc_box_release(buf);
out_free_cpsdr:
	ctf_msg(stk, "at out_free_cpsdr label\n");
	g_rc_box_release_full(cpsdr, cpsdr_release_memory);
	ctf_msg(stk, "error return NULL\n");
	return NULL;
}

void *
ctf_proto_stk_encode(const struct tof_msg *msg, size_t *ret_sz)
{
	char *buf;
	size_t buf_sz, cbor_sz;
	cbor_item_t *tof_cbor;
	struct sdu sdu;
	union sdu_ptr sdu_ptr;

	if (!(tof_cbor = tof_encode(msg)))
		return NULL;
	if (!(cbor_sz = cbor_serialized_size(tof_cbor)))
		goto out_free_cbor;
	buf_sz = cbor_sz + 2*sizeof(uint32_t);
	if (!(buf = calloc(1, buf_sz)))
		goto out_free_cbor;
	if (!cbor_serialize(tof_cbor, (unsigned char *)&buf[2*sizeof(uint32_t)], cbor_sz))
		goto out_free_buf;
	sdu.sdu_xmit = time(NULL);
	/* 0 is used everywhere I can find */
	sdu.sdu_proto_un.sdu_proto_num = mpn_trace_objects;
	/* false = initiator, true = responder */
	sdu.sdu_init_or_resp = false;
	sdu.sdu_len = cbor_sz;
	sdu.sdu_data = &buf[2*sizeof(uint32_t)];
	*ret_sz = buf_sz;
	sdu_ptr.sdu8 = (uint8_t *)buf;
	if (sdu_encode(&sdu, sdu_ptr))
		goto out_free_buf;
	ctf_cbor_decref(stk, &tof_cbor);
	return buf;
out_free_buf:
	free(buf);
out_free_cbor:
	ctf_cbor_decref(stk, &tof_cbor);
	return NULL;
}
