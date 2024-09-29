from struct import Struct
from construct import *

def parse_length(length_byte_struct, length_bytes):
    if not length_byte_struct.length_bytes:
        return length_byte_struct.length_value
    length = 0
    for i, length_byte in enumerate(length_bytes[::-1]):  # big endian
        length += length_byte * pow(0x100, i)
    return length
    
# generic MMS TLV
MMS_TLV = Struct(
    "type" / Byte,
    "_length_byte" / BitStruct("length_bytes" / Flag,
                               "length_value" / BitsInteger(7)),
    "length_bytes" / If(this._length_byte.length_bytes == True, Bytes(this._length_byte.length_value)),
    "length" / Computed(lambda x: parse_length(x._length_byte, x.length_bytes)),
    "data" / Bytes(this.length)
)

SERVICES_SUPPORTED = BitStruct(
    "status" / Flag,
    "get_name_list" / Flag,
    "identify" / Flag,
    "rename" / Flag,
    "read" / Flag,
    "write" / Flag,
    "get_variable_access_attributes" / Flag,
    "define_named_variable" / Flag,
    "define_scattered_access" / Flag,
    "get_scattered_access_attributes" / Flag,
    "delete_variable_access" / Flag,
    "define_named_variable_list" / Flag,
    "get_named_variable_list_attributes" / Flag,
    "delete_named_variable_list" / Flag,
    "define_named_type" / Flag,
    "get_named_type_attributes" / Flag,
    "delete_named_type" / Flag,
    "input" / Flag,
    "output" / Flag,
    "take_control" / Flag,
    "relinquish_control" / Flag,
    "define_semaphore" / Flag,
    "delete_semaphore" / Flag,
    "report_semaphore_status" / Flag,
    "report_pool_semaphore_status" / Flag,
    "report_semaphore_entry_status" / Flag,
    "initiate_download_sequence" / Flag,
    "download_segment" / Flag,
    "terminate_download_sequence" / Flag,
    "initiate_upload_sequence" / Flag,
    "upload_segment" / Flag,
    "terminate_upload_sequence" / Flag,
    "request_domain_download" / Flag,
    "request_domain_upload" / Flag,
    "load_domain_content" / Flag,
    "store_domain_content" / Flag,
    "delete_domain" / Flag,
    "get_domain_attributes" / Flag,
    "create_program_invocation" / Flag,
    "delete_program_invocation" / Flag,
    "start" / Flag,
    "stop" / Flag,
    "resume" / Flag,
    "reset" / Flag,
    "kill" / Flag,
    "get_program_invocation_attributes" / Flag,
    "obtain_file" / Flag,
    "define_event_condition" / Flag,
    "delete_event_condition" / Flag,
    "get_event_condition_attributes" / Flag,
    "report_event_condition_status" / Flag,
    "alter_event_condition_monitoring" / Flag,
    "trigger_event" / Flag,
    "define_event_action" / Flag,
    "delete_event_action" / Flag,
    "get_event_action_attributes" / Flag,
    "report_action_status" / Flag,
    "define_event_enrollment" / Flag,
    "delete_event_enrollment" / Flag,
    "alter_event_enrollment" / Flag,
    "report_event_enrollment_status" / Flag,
    "get_event_enrollment_attributes" / Flag,
    "acknowledge_event_notification" / Flag,
    "get_alarm_summary" / Flag,
    "get_alarm_enrollment_summary" / Flag,
    "read_journal" / Flag,
    "write_journal" / Flag,
    "initialize_journal" / Flag,
    "report_journal_status" / Flag,
    "create_journal" / Flag,
    "delete_journal" / Flag,
    "get_capability_list" / Flag,
    "file_open" / Flag,
    "file_read" / Flag,
    "file_close" / Flag,
    "file_rename" / Flag,
    "file_delete" / Flag,
    "file_directory" / Flag,
    "unsolicited_status" / Flag,
    "information_report" / Flag,
    "event_notification" / Flag,
    "attach_to_event_condition" / Flag,
    "attach_to_semaphore" / Flag,
    "conclude" / Flag,
    "cancel" / Flag,
    "reserved" / BitsInteger(3)
)