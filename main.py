import socket 
import struct
import dataclasses
from io import BytesIO
from dataclasses import dataclass
import dns.resolver
from parsers import *
from classes import *
from constants import *


def header_to_bytes(header):
    # This function converts classes to byte strings
    fields = dataclasses.astuple(header)

    # struct.pack converts the fields to bytes according to the format string (here !HHHHHH)
    return struct.pack('!HHHHHH', *fields) 

def question_to_bytes(question):
    return question.name + struct.pack('!HH', question.type_, question.class_)

def encode_dns_name(domain_name):
    # check if the input is a string or bytes object
    if isinstance(domain_name, bytes):
        domain_name = domain_name.decode("ascii")
    elif not isinstance(domain_name, str):
        raise ValueError("Input must be a string or bytes object")
    
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
    header = Header(id=id, flags=0, num_questions=1)
    questions = Question(name=name, type_=record_type, class_=1)

    # return the query parsed to bytes
    return header_to_bytes(header) + question_to_bytes(questions)

def send_query(ip_address="8.8.8.8", domain_name="dns.google.com", record_type=1):
    # build the query for the domain name assuming it is an A record
    # if it is a different record type, the program will fail.
    query = build_query(domain_name, record_type)
    
    # create a UDP socket
    # `socket.AF_INET` means that we're connecting to the internet
    # socket.SOCK_DGRAM means that we're using UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # send our query to 8.8.8.8, port 53. Port 53 is the DNS port
    # 8.8.8.8 is a public DNS server run by Google, so it is cheating to use this
    # The final goal is to implement a DNS resolver that can run by itself, without using any external DNS servers.
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_packet(data)

def decode_name_simple(reader):
    # This function fails if the name is compressed
    # It is here just to show how a simpler version of the more correct function would look like
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)

def decode_name(reader):
    # this is the improved version of decode_name_simple
    # sadly, it has a security vulnerability, but it works perfectly with compressed names

    parts = []
    while (length := reader.read(1)[0]) != 0:
        # check if the first two bits are 1s
        # if they are, it means the name is compressed
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            # since a compressed name is never followed by another label, we break the loop and return the final name
            break
        else:
            # normal name
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

def ip_to_string(ip):
    return ".".join([str(byte) for byte in ip])

def get_answer(packet):
    # return the first TYPE_A record in the answers
    for answer in packet.answers:
        if answer.type_ == TYPE_A:
            return answer.data

def get_nameserver_ip(packet):
    # return the first TYPE_A record in the Additional section
    for record in packet.additional:
        if record.type_ == TYPE_A:
            return record.data

def get_nameserver(packet):
    # return the first TYPE_NS record in the Authorities section
    for record in packet.authorities:
        if record.type_ == TYPE_NS:
            return record.data.decode("utf-8")

def get_cname(packet):
    # return the first TYPE_CNAME record in the Answers section
    for record in packet.answers:
        if record.type_ == TYPE_CNAME:
            return record.data.decode("utf-8")

def resolve(domain_name, record_type):
    '''
    This function resolves a domain name to an IP address.
    It starts by querying the root nameserver, and then it keeps querying the nameservers it gets until it gets an answer.
    '''
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        print(response)

        # if we got an answer, we return it
        if ip := get_answer(response):
            print("found an IP")
            print("--------------------")
            return ip
        # if we didn't get an answer, we check if we got a nameserver to keep looking 
        elif nsIP := get_nameserver_ip(response):
            # in the next iteration, we'll query the nameserver we got
            print("found a nameserver ip")
            print("--------------------")
            nameserver = nsIP
        elif ns_domain_name := get_nameserver(response):
            # if we got a nameserver, we resolve it to an IP address
            # and then we query the IP address
            print("found a nameserver domain name")
            print("--------------------")   
            nameserver = resolve(ns_domain_name, TYPE_A)
        elif cname := get_cname(response):
            # if we got a CNAME, we follow the CNAME chain
            print("found a CNAME")
            print("--------------------")
            return resolve(cname, TYPE_A)
        else:
            print("didn't find anything")
            return None

# ----------------------------------------------

def main(domain_name, record_type):
    response = resolve(domain_name, record_type)
    dns_python_response = str(dns.resolver.Resolver().resolve(domain_name, record_type)[0])
    if response == dns_python_response:
        print(f"{domain_name} resolved to {response}")
        print("Success!")
    else:
        print(f"This program resolved {domain_name} to {response}")
        print(f"Python DNS resolver resolved it to {dns_python_response}")

if __name__ == "__main__":
    main("wikipedia.org", TYPE_A)
