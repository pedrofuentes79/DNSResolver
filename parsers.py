from classes import *
from constants import TYPE_A, TYPE_NS, TYPE_CNAME
from utils import decode_name, ip_to_string, resolve
import struct
from io import BytesIO

def parse_header(reader):
    # !HHHHHH means that we're expecting 6 unsigned shorts (2 bytes each)
    # We read 12 bytes because we have 6*2 bytes in total
    items = struct.unpack('!HHHHHH', reader.read(12))
    return Header(*items) 

def parse_question(reader):
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack('!HH', data)
    return Question(name, type_, class_)

def parse_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    # HHIH means 2byte int, 2byte int, 4byte int, 2byte int
    type_, class_, ttl, data_length = struct.unpack('!HHIH', data)
    if type_ == TYPE_NS:
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_length))
    elif type_ == TYPE_CNAME:
        # CNAME is an alias, so we decode it as a name
        # then, we can resolve the name to an IP address
        cname_domain = decode_name(reader)
        data = resolve(cname_domain, TYPE_CNAME)
    else:
        data = reader.read(data_length)
    return Record(name, type_, class_, ttl, data)

def parse_packet(data):
    reader = BytesIO(data)
    # puts all pieces of the packet together
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additional = [parse_record(reader) for _ in range(header.num_additional)]

    return Packet(header, questions, answers, authorities, additional)
