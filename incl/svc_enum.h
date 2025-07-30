#pragma once

enum svc_result {
	svc_progress_fail = -1,
	svc_progress_none =  0,
	svc_progress_recv =  1,
	svc_progress_send =  2,
};

enum svc_req_result {
	svc_req_must_block,
	svc_req_success,
	svc_req_none_available,
	svc_req_failure,
};
