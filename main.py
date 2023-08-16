import socket 
import struct
import dataclasses
from io import BytesIO
from dataclasses import dataclass
import dns.resolver
from parsers import *
from classes import *
from constants import *
from utils import *


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
