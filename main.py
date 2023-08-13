import socket 
import struct
import dataclasses
from io import BytesIO
from dataclasses import dataclass

@dataclass
class Header:
    # Here we are ignoring most flags :)
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additional: int = 0

@dataclass
class Question:
    name: bytes # youtube.com
    type_: int  # A
    class_: int # (always the same)

@dataclass
class Record:
    name: bytes   # domain name
    type_: int    # A, AAAA, MX... (encoded as int)
    class_: int   # Always 1
    ttl: int      # How long to cache the query for. We'll ignore this
    data: bytes   # The record's content, like the IP address


def header_to_bytes(header):
    # This function converts classes to byte strings
    fields = dataclasses.astuple(header)

    # struct.pack converts the fields to bytes according to the format string (here !HHHHHH)
    return struct.pack('!HHHHHH', *fields) 

def question_to_bytes(question):
    return question.name + struct.pack('!HH', question.type_, question.class_)

def encode_dns_name(domain_name):
    #Splits the domain name into parts (["google", "com"]), encodes each part, and adds the length of each part before the part
    #So, google.com ends up as b'\x06google\xo3com\x00', because google is 6 characters long, and com is 3 characters long. 
    #The x00 is the end of the domain name
    encoded = b''
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b'\x00'


def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = 1337 #could have been random
    RECURSION_DESIRED = 1 << 8
    header = Header(id=id, flags=RECURSION_DESIRED, num_questions=1)
    questions = Question(name=name, type_=record_type, class_=1)

    # return the query parsed to bytes
    return header_to_bytes(header) + question_to_bytes(questions)

def parse_header(reader):
    # !HHHHHH means that we're expecting 6 unsigned shorts (2 bytes each)
    # We read 12 bytes because we have 6*2 bytes in total
    items = struct.unpack('!HHHHHH', reader.read(12))
    return Header(*items) 

def parse_question(reader):
    name = decode_name_simple(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack('!HH', data)
    return Question(name, type_, class_)

def parse_record(reader):
    # this function will break
    name = decode_name_simple(reader)

    data = reader.read(10)
    # HHIH means 2byte int, 2byte int, 4byte int, 2byte int
    type_, class_, ttl, data_length = struct.unpack('!HHIH', data)

    data = reader.read(data_length)
    return Record(name, type_, class_, ttl, data)


def decode_name_simple(reader):
    # this is kind of wrong, but will do until I figure out how to do it properly

    parts = []
    while (length := reader.read(1)[0]) != 0:
        print(length)
        parts.append(reader.read(length))
    return b".".join(parts)

def decode_name(reader):
    # this is the improved version of decode_name_simple
    # sadly, it has a security vulnerability.

    parts = []
    while (length := reader.read(1)[0]) != 0:
        # check if the first two bits are 1s
        # if they are, it means the name is compressed
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            # since a compressed name is never followed by another label, we break the loop and return the final name
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(length, reader):
    # the length is in the form of 11xxxxxx, where x is the pointer
    # so, we want to get the last 6 bits of the length, and add them to the next byte to get the pointer
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    
    # save current position in the reader
    current_pos = reader.tell()
    # go to the position pointed by the pointer
    reader.seek(pointer)
    # decode the name
    result = decode_name(reader)
    # go back to the position before we started reading the pointer
    reader.seek(current_pos)
    return result
# ----------------------------------------------

def main(domain_name):
    query = build_query(domain_name, record_type=1)
    # create a UDP socket
    # `socket.AF_INET` means that we're connecting to the internet
    # socket.SOCK_DGRAM means that we're using UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # send our query to 8.8.8.8, port 53. Port 53 is the DNS port
    # 8.8.8.8 is a public DNS server run by Google, so it is cheating to use this
    # The final goal is to implement a DNS resolver that can run by itself, without using any external DNS servers.
    sock.sendto(query, ("8.8.8.8", 53))

    # read the response. UDP DNS responses are at most 512 bytes, so reading 1024 is enough
    response, _ = sock.recvfrom(1024)

    reader = BytesIO(response)
    header = parse_header(reader)
    question = parse_question(reader)
    record = parse_record(reader)
    print(record)


if __name__ == "__main__":
    main("google.com")
