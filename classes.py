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

@dataclass
class Packet:
    header: Header
    questions: list[Question]
    answers: list[Record]
    authorities: list[Record]
    additional: list[Record]
