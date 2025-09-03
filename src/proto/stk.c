#include <cbor.h>
#include <time.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
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

	if (!(cpsdr = g_rc_box_new0(struct ctf_proto_stk_decode_result))) {
		ctf_msg(stk, "g_rc_box_new0() failed\n");
		return NULL;
	}
	sz = 2*sizeof(uint32_t);
	cur_sz = sz;
	cur_buf = (char *)hdr.sdu8;
	do {
		ret_sz = read(fd, cur_buf, cur_sz);
		if (ret_sz < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ctf_msg(stk, "read() failure (%d): %s\n", errno,
					strerror(errno));
			goto out_free_cpsdr;
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
	if (sdu_decode(hdr, &cpsdr->sdu) != RETVAL_SUCCESS) {
		ctf_msg(stk, "sdu_decode() failed\n");
		goto out_free_cpsdr;
	}
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
	tof_cbor = cbor_load(sdu_data_addr, sdu_data_len, load_result_addr);
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
	if (!tof_cbor) {
		ctf_msg(stk, "tof_cbor unexpectedly NULL\n");
		goto out_free_cpsdr;
	}
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
	case mpn_data_points:
	default:
		/* These cases return the CBOR uninterpreted w/elevated
		 * refcount. */
		cpsdr->proto_stk_decode_result_body.undecoded = tof_cbor;
		break;
	}
	return cpsdr;
out_free_tof_cbor:
	if (!!tof_cbor)
		ctf_cbor_decref(stk, &tof_cbor);
out_free_buf:
	g_rc_box_release(buf);
out_free_cpsdr:
	g_rc_box_release_full(cpsdr, cpsdr_release_memory);
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
