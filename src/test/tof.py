from ctypes import *

class trace_object(Structure):
    _fields_ = [ ("to_human", c_char_p)
               , ("to_machine", c_char_p)
               , ("to_namespace", POINTER(c_char_p))
               , ("to_severity", c_int)
               , ("to_details", c_int)
               , ("to_timestamp", c_time_t)
               , ("to_hostname", c_char_p)
               , ("to_thread_id", c_char_p)]

class tof_request(Structure):
    _fields_ = [ ("tof_blocking", c_bool)
               , ("tof_nr_obj", c_uint16)]

class tof_reply(Structure):
    _fields_ = [ ("tof_nr_replies", c_int)
               , ("tof_replies", POINTER(POINTER(trace_object)))]

class tof_msg_body(Union):
    _fields_ = [ ("request", tof_request)
               , ("reply", tof_reply)]

class tof_msg(Structure):
    _fields_ = [ ("tof_msg_type", c_int)
               , ("tof_msg_body", tof_msg_body)]
