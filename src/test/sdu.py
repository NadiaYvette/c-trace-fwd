from ctypes import *

class sdu(Structure):
    _fields_ = [ ("sdu_xmit", c_uint32)
               , ("sdu_proto_num", c_uint16)
               , ("sdu_len", c_uint16)
               , ("sdu_init_or_resp", c_bool)
               , ("sdu_data", c_char_p)]
