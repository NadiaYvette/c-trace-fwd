from ctypes import *

class handshake_propose_version_pair(Structure):
    _fields_ = [ ("propose_version_key", c_uint64)
               , ("propose_version_value", c_void_p)]

class handshake_propose_versions(Structure):
    _fields_ = [ ("handshake_propose_versions", handshake_propose_version_pair)
               , ("handshake_propose_versions_len", c_int)]

class handshake_accept_version(Structure):
    _fields_ = [ ("handshake_accept_version_number", c_uint64)
               , ("handshake_accept_version_params", c_void_p)]

class handshake_refusal_version_mismatch(Structure):
    _fields_ = [ ("handshake_refusal_version_mismatch_len", c_int)
               , ("handshake_refusal_version_mismatch_versions",
                                                   POINTER(c_uint64))]

class handshake_refusal_decode_error(Structure):
    _fields_ = [ ("handshake_refusal_decode_error_version", c_uint64)
               , ("handshake_refusal_decode_error_string", c_char_p)]

class handshake_refusal_refused(Structure):
    _fields_ = [ ("handshake_refusal_refused_version", c_uint64)
               , ("handshake_refusal_refused_string", c_char_p)]

class handshake_refusal_message(Union):
    _fields_ = [ ("version_mismatch", handshake_refusal_version_mismatch)
               , ("decode_error", handshake_refusal_decode_error)
               , ("refused", handshake_refusal_refused)]

class handshake_refusal(Structure):
    _fields_ = [ ("reason_type", c_int)
               , ("refusal_message", handshake_refusal_message)]

class handshake_query_reply_pair(Structure):
    _fields_ = [ ("query_reply_key", c_uint64)
               , ("query_reply_value", c_void_p)]

class handshake_query_reply(Structure):
    _fields_ = [ ("handshake_query_reply_Len", c_int)
               , ("handshake_query_reply",
                                     POINTER(handshake_query_reply_pair))]

class handshake_message(Union):
    _fields_ = [ ("propose_versions", handshake_propose_versions)
               , ("accept_version", handshake_accept_version)
               , ("refusal", handshake_refusal)
               , ("query_reply", handshake_query_reply)]

class handshake(Structure):
    _fields_ = [ ("handshake_type", c_int)
               , ("handshake_message", handshake_message)]
