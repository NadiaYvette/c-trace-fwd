#include <cbor.h>
#include <linux/errno.h>
#include <time.h>
#include <sys/ioctl.h>
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
	union msg *msg;

	if (cpsdr->buf)
		g_rc_box_release(cpsdr->buf);

	if (cpsdr->load_result.error.code != CBOR_ERR_NONE)
		return;
	if (!(msg = cpsdr->proto_stk_decode_result_body))
		return;
	switch (cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
	case mpn_handshake:
		handshake_free((struct handshake *)msg);
		break;
	case mpn_trace_objects:
		tof_free(&msg->tof_msg);
		break;
	case mpn_EKG_metrics:
	case mpn_data_points:
	case mpn_node_tx_submit:
	case mpn_chain_sync:
	case mpn_client_tx_submit:
	case mpn_state_query:
	case mpn_keepalive:
		union msg **cbor_ref;

		cbor_ref = &cpsdr->proto_stk_decode_result_body;
		ctf_cbor_decref(stk, (cbor_item_t **)cbor_ref);
		break;
	default:
		ctf_msg(ctf_alert, stk, "bad mpn %d\n",
			(int)cpsdr->sdu.sdu_proto_un.sdu_proto_num);
		break;
	}
	cpsdr->proto_stk_decode_result_body = NULL;
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

	ctf_msg(ctf_debug, stk, "enter\n");
	if (!(cpsdr = g_rc_box_new0(struct ctf_proto_stk_decode_result))) {
		ctf_msg(ctf_alert, stk, "g_rc_box_new0() failed\n");
		return NULL;
	}
	sz = 2*sizeof(uint32_t);
	cur_sz = sz;
	cur_buf = (char *)hdr.sdu8;
	ctf_msg(ctf_debug, stk, "starting SDU IO loop\n");
	do {
		ctf_msg(ctf_debug, stk, "read(%d, %p, %zu)\n", fd, cur_buf,
				cur_sz);
		ret_sz = read(fd, cur_buf, cur_sz);
		ctf_msg(ctf_debug, stk,
				"read(%d, %p, %zu) = %zd\n", fd, cur_buf,
				cur_sz, ret_sz);
		if (ret_sz < 0) {
			ctf_msg(ctf_alert, stk, "negative branch\n");
			if (errno_is_restart(errno))
				continue;
			ctf_msg(ctf_alert, stk,
					"read() failure (%d): %s\n",
					errno, strerror(errno));
			goto out_free_cpsdr;
		} else if (!ret_sz) {
			int buf_cnt = -1;

			ctf_msg(ctf_debug, stk,
					"zero case retry %u\n", retries);
			if (!errno_is_restart(errno)) {
				ctf_msg(ctf_alert, stk,
					"read() failure (%d): %s\n",
					errno, strerror(errno));
				goto out_free_cpsdr;
			}
			if (!!ioctl(fd, FIONREAD, &buf_cnt)) {
				ctf_msg(ctf_alert, stk,
					"FIONREAD failure (%d): %s\n",
					errno, strerror(errno));
				goto out_free_cpsdr;
			}
			ctf_msg(ctf_debug, stk, "buf_cnt = %d\n", buf_cnt);
			if (!buf_cnt) {
				int flg;

				if ((flg = fcntl(fd, F_GETFL)) == -1) {
					ctf_msg(ctf_alert, stk,
						"fcntl failure (%d): %s\n",
						errno, strerror(errno));
					goto out_free_cpsdr;
				}
				render_flags(stk, flg);
			}
			if (++retries >= retry_limit) {
				ctf_msg(ctf_alert, stk,
						"retry limit reached!\n");
				goto out_free_cpsdr;
			}
			(void)!sched_yield();
			continue;
		} else if (ret_sz < cur_sz) {
			ctf_msg(ctf_debug, stk,
					"bounded above by cur_sz branch\n");
			cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
			cur_sz -= MIN(cur_sz, ret_sz);
			(void)!sched_yield();
			continue;
		} else {
			ctf_msg(ctf_debug, stk, "ret_sz >= 0 && "
					"ret_sz >= cur_sz branch?\n");
			ctf_msg(ctf_debug, stk,
					"ret_sz = %zd, cur_sz = %zu\n",
					ret_sz, cur_sz);
			assert(ret_sz == cur_sz);
			break;
		}
	} while (cur_sz > 0);
	ctf_msg(ctf_debug, stk, "finished SDU IO loop\n");
	if (sdu_decode(hdr, &cpsdr->sdu) != RETVAL_SUCCESS) {
		ctf_msg(ctf_alert, stk, "sdu_decode() failed\n");
		goto out_free_cpsdr;
	}
	ctf_msg(ctf_debug, stk, "received SDU:\n");
	sdu_print(&cpsdr->sdu);
	cpsdr->sdu.sdu_data = (const char *)&hdr.sdu32[2];
	load_result_addr = &cpsdr->load_result;
	if (!(buf = g_rc_box_alloc0(65 * 1024))) {
		ctf_msg(ctf_alert, stk, "buf calloc() failed\n");
		goto out_free_cpsdr;
	}
	cpsdr->buf = buf;
	(void)!memcpy(&buf[0], &sdu, 2*sizeof(uint32_t));
	cpsdr->sdu.sdu_data = &buf[2*sizeof(uint32_t)];
	sdu_data_addr = (cbor_data)cpsdr->sdu.sdu_data;
	sdu_data_len  = cpsdr->sdu.sdu_len;
	sz = sdu_data_len;
	cur_sz = sz;
	cur_buf = (char *)sdu_data_addr;
	ctf_msg(ctf_debug, stk, "starting CBOR payload IO loop\n");
	do {
		ret_sz = read(fd, cur_buf, cur_sz);
		if (ret_sz < 0) {
			if (errno_is_restart(errno))
				continue;
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
	ctf_msg(ctf_debug, stk, "finished CBOR payload IO loop\n");
	ctf_msg(ctf_debug, stk, "doing cbor_load() on payload\n");
	tof_cbor = cbor_load(sdu_data_addr, sdu_data_len, load_result_addr);
	ctf_msg(ctf_debug, stk, "got past payload cbor_load()\n");
	ctf_msg(ctf_debug, stk, "checking ->error.code\n");
	switch (load_result_addr->error.code) {
	case CBOR_ERR_NONE:
		break;
	case CBOR_ERR_NOTENOUGHDATA:
		ctf_msg(ctf_alert, stk,
				"CBOR_NOTENOUGHDATA returned by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(ctf_alert, stk,
					"tof_cbor != NULL (%p) despite "
					"CBOR_ERR_NOTENOUGHDATA?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		return cpsdr;
	case CBOR_ERR_NODATA:
		ctf_msg(ctf_alert, stk,
				"CBOR_ERR_NODATA returned "
				"by cbor_load(%zd)\n",
				sdu_data_len);
		sdu_print(&cpsdr->sdu);
		if (!!tof_cbor) {
			ctf_msg(ctf_alert, stk,
					"tof_cbor != NULL (%p) despite "
					"CBOR_ERR_NODATA?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		return cpsdr;
	case CBOR_ERR_MALFORMATED:
		ctf_msg(ctf_alert, stk,
				"CBOR_ERR_MALFORMATED returned "
				"by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(ctf_alert, stk,
					"tof_cbor != NULL (%p) despite "
					"CBOR_ERR_MALFORMATED?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		return cpsdr;
	case CBOR_ERR_MEMERROR:
		ctf_msg(ctf_alert, stk,
				"CBOR_ERR_MEMERROR returned "
				"by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(ctf_alert, stk,
					"tof_cbor != NULL (%p) despite "
					"CBOR_ERR_MEMERROR?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		return cpsdr;
	case CBOR_ERR_SYNTAXERROR:
		ctf_msg(ctf_alert, stk,
				"CBOR_ERR_SYNTAXERROR returned "
				"by cbor_load()\n");
		if (!!tof_cbor) {
			ctf_msg(ctf_alert, stk,
					"tof_cbor != NULL (%p) despite "
					"CBOR_ERR_SYNTAXERROR?\n",
					tof_cbor);
			goto out_free_tof_cbor;
		}
		return cpsdr;
	default:
		ctf_msg(ctf_alert, stk,
				"unrecognized error code %d returned"
			       " by cbor_load()\n",
			       load_result_addr->error.code);
		if (!!tof_cbor)
			ctf_msg(ctf_alert, stk,
					"tof_cbor != NULL (%p) despite "
					"unrecognized error code?\n",
					tof_cbor);
		return cpsdr;
	}
	ctf_msg(ctf_debug, stk, "got past ->error.code check\n");
	if (!tof_cbor) {
		ctf_msg(ctf_debug, stk, "tof_cbor unexpectedly NULL\n");
		goto out_free_cpsdr;
	}
	ctf_msg(ctf_debug, stk, "checking miniprotocol nr\n");
	switch (cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
	case mpn_handshake:
		cpsdr->proto_stk_decode_result_body
			= (union msg *)handshake_decode(tof_cbor);
		if (!cpsdr->proto_stk_decode_result_body) {
			ctf_msg(ctf_alert, stk,
					"handshake_decode() failed\n");
			goto out_free_tof_cbor;
		}
		ctf_cbor_decref(stk, &tof_cbor);
		break;
	case mpn_trace_objects:
		if (!(cpsdr->proto_stk_decode_result_body = (union msg *)tof_decode(tof_cbor))) {
			ctf_msg(ctf_alert, stk, "tof_decode() failed\n");
			goto out_free_tof_cbor;
		}
		/* This case translates the CBOR to C trace object data
		 * structures and discards the intermediate CBOR results. */
		ctf_cbor_decref(stk, &tof_cbor);
		break;
	case mpn_EKG_metrics:
		ctf_msg(ctf_debug, stk, "mpn_EKG_metrics packet\n");
	case mpn_data_points:
		if (cpsdr->sdu.sdu_proto_un.sdu_proto_num == mpn_data_points)
			ctf_msg(ctf_debug, stk, "mpn_data_points packet\n");
	default:
		/* These cases return the CBOR uninterpreted w/elevated
		 * refcount. Empty replies need to be sent to requests. */
		if (!MPN_VALID(cpsdr->sdu.sdu_proto_un.sdu_proto_num))
			ctf_msg(ctf_alert, stk,
					"packet w/unhandled "
					"miniprotocol %d\n",
				(int)cpsdr->sdu.sdu_proto_un.sdu_proto_num);
		cpsdr->proto_stk_decode_result_body = (union msg *)tof_cbor;
		ctf_msg(ctf_alert, stk, "cpsdr = %p\n", cpsdr);
		ctf_msg(ctf_alert, stk,
				"cpsdr->proto_stk_decode_result_body = %p\n",
				cpsdr->proto_stk_decode_result_body);
		break;
	}
	ctf_msg(ctf_debug, stk, "past miniprotocol nr check\n");
	ctf_msg(ctf_debug, stk, "return %p\n", cpsdr);
	return cpsdr;
out_free_tof_cbor:
	ctf_msg(ctf_debug, stk, "at out_free_tof_cbor label\n");
	if (!!tof_cbor)
		ctf_cbor_decref(stk, &tof_cbor);
out_free_cpsdr:
	ctf_msg(ctf_debug, stk, "at out_free_cpsdr label\n");
	if (ctf_check_ptr(stk, cpsdr))
		ctf_msg(ctf_debug, stk, "invalid ptr %p\n", cpsdr);
	else if (!!cpsdr) {
		ctf_msg(ctf_debug, stk, "trying to release %p\n", cpsdr);
		g_rc_box_release_full(cpsdr, cpsdr_release_memory);
	}
	ctf_msg(ctf_debug, stk, "error return NULL\n");
	return NULL;
}

void *
tof_proto_stk_encode(const struct tof_msg *msg, size_t *ret_sz)
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
	sdu.sdu_init_or_resp = CTF_INIT_OR_RESP;
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

void *
ctf_proto_stk_encode(enum mini_protocol_num mpn, const union msg *msg, size_t *ret_sz)
{
	switch (mpn) {
	case mpn_trace_objects:
		return tof_proto_stk_encode(&msg->tof_msg, ret_sz);
	case mpn_EKG_metrics:
		return build_empty_metrics_resp();
	case mpn_data_points:
		return build_empty_datapoint_resp();
	default:
		return NULL;
	}
}
