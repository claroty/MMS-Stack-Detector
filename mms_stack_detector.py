import argparse
import socket
import os
from construct import *
from bitarray import bitarray
from enum import Enum
from struct import pack
from mms_structs import *


class MMSDetectionFailed(Exception):
    pass


# Some hard coded values
DEFAULT_MMS_PORT = 102

MMS_PDU_TYPE_INIT_REQ = 0xa9
MMS_PDU_TYPE_IDENTIFY_REQ = 0xa2

TPKT_LAYER_LEN = 4


class TPDU_Types(Enum):
    TPDU_CONNECTION_REQUEST = 1
    TPDU_DATA = 2


# The signarure data base
known_signatures = [
    {
        "Name": "LibIEC61850",
        "Required": bitarray('1110111000011100000000000000000000000000000000000000000000000000000000000000000100011000'),
        "Optional": bitarray('0000000000000000000000000000000000000000000000100000000000000000010000001111110000000000')
    },
    {
        "Name": "Triangle MicroWorks MMSd",
        "Required": bitarray('1110111000011100000000000000000000000100000000000000000000000000011110010000001100011000'),
        "Optional": bitarray('0000000000000000000000000011100000000000000000100000000000000000000000001110110000000000')
    },
    {
        "Name": "Sisco MMS Lite",
        "Required": bitarray('1110111000011100000000000000000000000100000000000000000000000000010110011110010100011000'),
        "Optional": bitarray('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    },
    {
        "Name": "INFO TECH S61850",
        "Required": bitarray('1110111000011100000000000000000000000100000000000000000000000000000000011110110100010000'),
        "Optional": bitarray('0000000000000000000000000000000000000000000000100000000000000000000000000000000000001000')
    },
    {
        "Name": "Vizimax",
        "Required": bitarray('1110111000011100000000000000000000000100000000000000000000000000000000001110110100011000'),
        "Optional": bitarray('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    },
    {
        "Name": "Bitronics",
        "Required": bitarray('1110111000011100000000000000000000000100000000000000000000000000000000011110110000011000'),
        "Optional": bitarray('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    }
]


def print_prologue(server_ip):
    print("")
    print("-------------------------- MMS Stack Detector ---------------------------")
    print(
        f"---------------------------[{server_ip:^15}]-----------------------------")
    print("")


def print_epilogue():
    print("=========================================================================\n\n\n")


def print_separator():
    print("-------------------------------------------------------------------------")


def print_services(services_bytes):
    print("[*] Supported services:\n")
    services = SERVICES_SUPPORTED.parse(services_bytes)
    for service, flag in services.items():
        if '_io' not in service:
            print(f"    [{'*' if flag else ' '}] {service}")
    print("")


def exit_detection():
    print_epilogue()
    raise MMSDetectionFailed


def get_rfc1006_payload(tpdu_type, higher_layers_lenght):
    if tpdu_type == TPDU_Types.TPDU_CONNECTION_REQUEST:
        ISO_8073_LAYER =  b'\x11'             # Length
        ISO_8073_LAYER += b'\xe0'             # PDU Type: CR Connect Request
        ISO_8073_LAYER += b'\x00\x00'         # Destination reference
        ISO_8073_LAYER += b'\x00\x01'         # Source reference
        ISO_8073_LAYER += b'\x00'             # class + COTP flags
        ISO_8073_LAYER += b'\xc0\x01\x0a'     # tpdu-size
        ISO_8073_LAYER += b'\xc1\x02\x00\x01' # src-tsap
        ISO_8073_LAYER += b'\xc2\x02\x00\x01' # dst-tsap

    elif tpdu_type == TPDU_Types.TPDU_DATA:
        ISO_8073_LAYER =  b'\x02'   # Length
        ISO_8073_LAYER += b'\xf0'   # PDU Type: DT Data (0x0f)
        ISO_8073_LAYER += b'\x80'   # TPDU number + Is Last

    else:
        print("ERROR TPDU Type")
        exit_detection()

    TPKT = b'\x03\x00'  # Version + reserved
    TPKT += pack(">H", TPKT_LAYER_LEN +
                 len(ISO_8073_LAYER) + higher_layers_lenght)
    return TPKT + ISO_8073_LAYER


def get_osi_layers_initiatePDU(include_acse=False):

    # Session layer
    IS0_8327_LAYER =  b'\x0d'                                #    SPDU Type
    IS0_8327_LAYER += b'\xb6'                                #    Length
    IS0_8327_LAYER += b'\x05\x06\x13\x01\x00\x16\x01\x02'    #    Connect Accept Item
    IS0_8327_LAYER += b'\x14\x02\x00\x02'                    #    Session Requirement
    IS0_8327_LAYER += b'\x33\x02\x00\x01'                    #    Calling Session Selector
    IS0_8327_LAYER += b'\x34\x02\x00\x01'                    #    Called Session Selector
    IS0_8327_LAYER += b'\xc1\xa0'                            #    Session user data\

    # Presentation Layer ASN.1 BER Encoded
    ISO_8823_LAYER = b'\x31\x81'
    ISO_8823_LAYER += b'\x9d'
    ISO_8823_LAYER += b'\xa0\x03\x80\x01\x01'                   # mode-value
    ISO_8823_LAYER += b'\xa2\x81\x95'
    ISO_8823_LAYER += b'\x81\x04\x00\x00\x00\x01'               # calling-presentation-selector 
    ISO_8823_LAYER += b'\x82\x04\x00\x00\x00\x01'               # called-presentation-selector
    ISO_8823_LAYER +=   b'\xa4\x23' 
    ISO_8823_LAYER +=     b'\x30\x0f'
    ISO_8823_LAYER +=      b'\x02\x01\x01'                      # presentation-context-identifier
    ISO_8823_LAYER +=      b'\x06\x04\x52\x01\x00\x01'          # abstract-syntax-name
    ISO_8823_LAYER +=      b'\x30\x04\x06\x02\x51\x01'          # transfer-syntax-name-list
    ISO_8823_LAYER +=     b'\x30\x10'
    ISO_8823_LAYER +=      b'\x02\x01\x03'                      # presentation-context-identifier
    ISO_8823_LAYER +=      b'\x06\x05\x28\xca\x22\x02\x01'      # abstract-syntax-name
    ISO_8823_LAYER +=      b'\x30\x04\x06\x02\x51\x01'          # transfer-syntax-name-list
    ISO_8823_LAYER +=   b'\x61\x62\x30\x60\x02\x01\x01\xa0\x5b' # user-data

    # Application Layer ASN.1 BER Encoded
    ISO_8650_LAYER = b'\x60\x59'
    ISO_8650_LAYER +=   b'\xa1\x07\x06\x05\x28\xca\x22\x02\x03'           # aSO-context-name
    ISO_8650_LAYER +=   b'\xa2\x07\x06\x05\x29\x01\x87\x67\x01'           # called-AP-title
    ISO_8650_LAYER +=   b'\xa3\x03\x02\x01\x0c'                           # called-AE-qualifier
    ISO_8650_LAYER +=   b'\xa6\x06\x06\x04\x29\x01\x87\x67'               # calling-AP-title
    ISO_8650_LAYER +=   b'\xa7\x03\x02\x01\x0c'                           # calling-AE-qualifier
    ISO_8650_LAYER +=   b'\xbe\x33\x28\x31\x06\x02\x51\x01\x02\x01\x03'   # user-information: Association-data
    ISO_8650_LAYER +=       b'\xa0\x28'                                   # MMS data 
    
    if include_acse:
        return IS0_8327_LAYER + ISO_8823_LAYER + ISO_8650_LAYER
    else:
        return IS0_8327_LAYER + ISO_8823_LAYER


def get_osi_layers_confirmedPDU():

    # Session layer
    IS0_8327_LAYER_1 = b'\x01\x00' #SPDU Type + lenght
    IS0_8327_LAYER_2 = b'\x01\x00' #SPDU Type + lenght

    # Presentation Layer ASN.1 BER Encoded
    ISO_8823_LAYER = b'\x61\x0f'            # User Data
    ISO_8823_LAYER += 	b'\x30\x0d'         # PVD List
    ISO_8823_LAYER +=       b'\x02\x01\x03' # presentation-context-identifier
    ISO_8823_LAYER +=       b'\xa0\x08'     # presentation-data-values

    return IS0_8327_LAYER_1 + IS0_8327_LAYER_2 + ISO_8823_LAYER


def get_inititiadeRequest(is_reduced_osi):

    MMS_MSG = b'\xa8\x26'                                                       # initiate-RequestPDU
    MMS_MSG +=  b'\x80\x03\x00\xff\x00'                                         # localDetailCalling
    MMS_MSG +=  b'\x81\x01\x01'                                                 # proposedMaxServOutstandingCalling
    MMS_MSG +=  b'\x82\x01\x01'                                                 # proposedMaxServOutstandingCalled
    MMS_MSG +=  b'\x83\x01\x0a'                                                 # proposedDataStructureNestingLevel
    MMS_MSG +=  b'\xa4\x16'                                                     # mmsInitRequestDetail
    MMS_MSG +=      b'\x80\x01\x01'                                             # proposedVersionNumber
    MMS_MSG +=      b'\x81\x03\x05\xf1\x00'                                     # padding + proposedParameterCBB
    MMS_MSG +=      b'\x82\x0c\x03\xee\x1c\x00\x00\x04\x02\x00\x00\x01\xed\x18' # padding + servicesSupportedCalling
    
    if is_reduced_osi:
        CONSTRUCTED = MMS_MSG
    else:
        CONSTRUCTED = get_osi_layers_initiatePDU(True) + MMS_MSG

    RFC1006 = get_rfc1006_payload(TPDU_Types.TPDU_DATA, len(CONSTRUCTED))

    return RFC1006 + CONSTRUCTED


def get_identifyRequest(is_reduced_osi):

    MMS_MSG = b'\xa0\x06'               # confirmed-RequestPDU
    MMS_MSG += 	b'\x02\x02\x11\x4f'     # invokeID
    MMS_MSG += 	b'\x82\x00'             # confirmedServiceRequest

    if is_reduced_osi:
        CONSTRUCTED = MMS_MSG
    else:
        CONSTRUCTED = get_osi_layers_confirmedPDU() + MMS_MSG

    RFC1006 = get_rfc1006_payload(TPDU_Types.TPDU_DATA, len(CONSTRUCTED))

    return RFC1006 + CONSTRUCTED


def get_mms_identification(server, is_reduced_osi):
    try:
        response = get_identify_response(server, is_reduced_osi)
    except Exception as e:
        print(
            f"ERROR: Something went wrong while sending identification request, got exception: {e}")
        exit_detection()
    return parse_identify_response(response)


def get_initialize_response(server, is_reduced_osi=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((server, DEFAULT_MMS_PORT))
    sock.send(get_rfc1006_payload(TPDU_Types.TPDU_CONNECTION_REQUEST, 0))
    sock.recv(1024)
    sock.send(get_inititiadeRequest(is_reduced_osi))
    resp = sock.recv(1024)
    sock.close()
    return resp


def get_identify_response(server, is_reduced_osi=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((server, DEFAULT_MMS_PORT))
    sock.send(get_rfc1006_payload(TPDU_Types.TPDU_CONNECTION_REQUEST, 0))
    sock.recv(1024)
    sock.send(get_inititiadeRequest(is_reduced_osi))
    resp = sock.recv(1024)
    sock.send(get_identifyRequest(is_reduced_osi))
    resp = sock.recv(1024)
    sock.close()
    return resp


def get_mms_stack_signature(server):
    sig_done = bitarray(endian='big')
    is_reduced_osi = False
    response_init = None
    try:
        response_init = get_initialize_response(server)
    except Exception:
        is_reduced_osi = True

    if response_init == None or response_init == b'' or is_reduced_osi is True:
        is_reduced_osi = True
        print("ERROR: Did not get a response, trying ABB mode")
        try:
            response_init = get_initialize_response(
                server, is_reduced_osi)
            if response_init == None or response_init == b'':
                print("ERROR: Something went wrong, did not get a response, exiting...")
                exit_detection()
        except ConnectionResetError:
            print(
                "ERROR: Something went wrong, could not connect to the server, exiting...")
            exit_detection()
        except socket.timeout:
            print("ERROR: Something went wrong, did not get a response, exiting...")
            exit_detection()

    signature = get_initiate_response_mms_data(response_init)

    if signature is None:
        print("ERROR: Failed to parse the payload, please open an issue so we could fix it")
        exit_detection()

    sig_done.frombytes(signature)

    vendor_name, model, version = get_mms_identification(
        server, is_reduced_osi)

    return sig_done, vendor_name, model, version


def get_initiate_response_mms_data(data):
    """
    This function is used to extract the MMS data from the response to the initial initiate-request packet,
    as we don't want to deal with parsing the layers before MMS (ISO 8327-1, ISO 8823, ISO 8650-1).
    So we're just looking for the first byte of the MMS response and try to parse the data from there.
    :param data: the data over COTP returned from after sending initiate-RequestPDU
    :return: only the MMS Data, as bytes
    """
    offsets = [i for i in range(len(data)) if data[i] == MMS_PDU_TYPE_INIT_REQ]

    if len(offsets) == 0:
        return None

    return get_supported_services_from_mms_payload(data[offsets[0]:])


def get_supported_services_from_mms_payload(raw_data):
    parsed_raw = MMS_TLV.parse(raw_data)

    if parsed_raw.type != MMS_PDU_TYPE_INIT_REQ:
        print(
            "ERROR: Something went wrong, this is not an initiate_ResponsePDU, exiting...")
        exit_detection()

    parsed_raws = Struct("tlvs" / GreedyRange(MMS_TLV)).parse(parsed_raw.data)
    for tlv in parsed_raws.tlvs:
        if tlv.type == 0xa4:
            return get_supported_services_bitmap(tlv)


def get_supported_services_bitmap(main_tlv):
    parsed_raws = Struct("tlvs" / GreedyRange(MMS_TLV)).parse(main_tlv.data)
    for tlv in parsed_raws.tlvs:
        if tlv.type == 0x82:
            temp = Struct("padding" / Byte,
                          "services_supported" / Bytes(11)).parse(tlv.data)
            return temp.services_supported

    print("ERROR: Something went wrong, didn't find servicesSupportedCalled, exiting...")
    exit_detection()

# It will much better to parse the prev to MMS layers instead of serching for the pdu type..
def parse_identify_response(data):
    offsets = [i for i in range(len(data)) if data[i]
               == MMS_PDU_TYPE_IDENTIFY_REQ]
    if len(offsets) == 0:
        print("ERROR: Something went wrong, failed to parse identify response")
        return None

    parsed_raws = Struct("tlvs" / GreedyRange(MMS_TLV)
                         ).parse(data[offsets[0]:])
    for tlv in parsed_raws.tlvs:
        if tlv.type == 0xa2:
            indentify_data = GreedyRange(MMS_TLV).parse(tlv.data)
            if len(indentify_data) < 3:
                print("ERROR: Something went wrong, failed to parse identify response")
            vendor_name = indentify_data[0].data.decode('utf-8')
            model_name = indentify_data[1].data.decode('utf-8')
            revision_name = indentify_data[2].data.decode('utf-8')
            return vendor_name, model_name, revision_name
    return None


def print_detection_one_server(server_ip, print_all_services):
    print_prologue(server_ip)

    stack_signature, vendor_name, model, version = get_mms_stack_signature(
        server_ip)

    if vendor_name is not None and model is not None and version is not None:
        print(
            f"[*] Server Identification \n\tVendor Name: {vendor_name}\n\tModel: {model}\n\tVersion: {version}")
        print_separator()
    else:
        print("[!] Server Identification \n\tParsing failed...")
        print_separator()

    guessed_stack = None
    for signature in known_signatures:

        # Ignore optional bits by ANDing it with NEG(Optional bit array)
        if not ((stack_signature ^ signature['Required']) & (~signature['Optional'])).any():
            guessed_stack = signature['Name']
            break

    if print_all_services:
        print_services(stack_signature.tobytes())
        print_separator()

    if guessed_stack is None:
        print(
            f"[!] Unrecognized Stack: Please open an issue so we can add it. Signature: [0x{stack_signature.tobytes().hex()}]")
    else:
        print(
            f"[*] MMS Stack: {guessed_stack} Sig [0x{stack_signature.tobytes().hex()}]")
    print_epilogue()


def main():
    # Example: python3 mms_stack_detector.py --server_ip 10.10.10.10 --print_all_services
    parser = argparse.ArgumentParser(description='MMS Stack Detector')
    parser.add_argument('--server_ip', help='Server/Device IP address')
    parser.add_argument('--from_file',
                        help='Specify file path of IP addresses separated by newline')
    parser.add_argument('--print_all_services', action='store_true',
                        help='Whether to print the services along with the detected MMS stack')

    args = parser.parse_args()

    if args.server_ip is not None:
        try:
            print_detection_one_server(args.server_ip, args.print_all_services)
        except MMSDetectionFailed:
            exit()
    elif args.from_file is not None and os.path.exists(args.from_file):
        with open(args.from_file, 'r') as f:
            for line in f.readlines():
                try:
                    print_detection_one_server(
                        line.strip(), args.print_all_services)
                except MMSDetectionFailed:
                    continue
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
