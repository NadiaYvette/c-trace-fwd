from ctypes import *
from ctypes.util import *
from handshake import *
from sdu import *
from tof import *

class Main():
    def loadlib():
        lib = cdll.LoadLibrary("./obj/lib/libc_trace_fwd.so")
        lib.ctf_proto_stk_decode.argtypes = [c_void_p]
        lib.ctf_proto_stk_decode.restype  = POINTER(tof_msg)
        lib.ctf_proto_stk_encode.argtypes = [POINTER(tof_msg), POINTER(c_size_t)]
        lib.ctf_proto_stk_encode.restype  = c_void_p
