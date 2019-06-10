import base64

# class Server
from os import system
from typing import List

import scapy
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sniff

queries_liste = {}  # Global variable
quiet = False
databaseConn = None
databaseCursor = None


def decode_from_base32(enc_mes):
    enc_mes = enc_mes.replace('.', '')
    b = bytes(enc_mes, 'utf-8')
    mes = base64.b32decode(b)
    b = str(mes, 'utf-8')
    return b


def write_to_file(lst: List[str]):
    str = ""
    for i in range(0, lst.__len__()):
        lst[i] = decode_from_base32(lst[i])
        str += lst[i]
    with open("Output.txt", mode="w", encoding="utf-8") as file:
        file.write(str)


def address_contained(x: bytes):
    x = str(x, 'utf-8')
    if "legit-domain.demo" in x:
        x = x.split("legit-domain.demo")[0]
        return decode_from_base32(x)
    return ""


def check_list_len():
    x = str(x, 'utf-8')
    if "legit-domain.demo" in x:
        x = x.split("legit-domain.demo")[0]
        return x
    return ""


def stopfilter(x):
    global lst
    global list_len
    if lst.__len__() == list_len and list_len>0:
        return True
    else:
        return False


def process(pkt):
    global quiet
    global databaseConn
    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53:
        # pkt[IP].dst == IP source of the DNS request
        # pkt[IP].src == IP of the DNS server
        # pkt[DNS].an.rrname == DNS name
        query = pkt[DNS].an.rrname if pkt[DNS].an != None else "?"

        if not pkt[IP].dst in queries_liste:
            queries_liste[pkt[IP].dst] = {}

        if not pkt[IP].src in queries_liste[pkt[IP].dst]:
            queries_liste[pkt[IP].dst][pkt[IP].src] = {}

        if not query in queries_liste[pkt[IP].dst][pkt[IP].src]:
            queries_liste[pkt[IP].dst][pkt[IP].src][query] = 1
        else:
            queries_liste[pkt[IP].dst][pkt[IP].src][query] += 1

        if databaseConn and query != None and None != "?":
            databaseCursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?);", (query,))
            databaseConn.commit()

            databaseCursor.execute("SELECT idDomain FROM domains WHERE domain=?;", (query,))
            domainId = databaseCursor.fetchone()[0]

            databaseCursor.execute("SELECT count, idWhoAsk FROM whoAsk WHERE ipFrom=? AND ipTo=? AND domainId=?;",
                                   (pkt[IP].src, pkt[IP].dst, domainId))
            whoAsk = databaseCursor.fetchone()

            if whoAsk:
                databaseCursor.execute("UPDATE whoAsk SET count=? WHERE idWhoAsk=?",
                                       (whoAsk[0] + 1 if whoAsk[0] else 2, whoAsk[1]))
            else:
                databaseCursor.execute("INSERT INTO whoAsk (ipFrom, ipTo, domainId, count) VALUES (?,?,?,1);",
                                       (pkt[IP].src, pkt[IP].dst, domainId))

            databaseConn.commit()

        if not quiet:

            print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))
            for ip in queries_liste:
                print("{:15s}".format(ip))  # IP source
                for query_server in queries_liste[ip]:
                    print(" " * 18 + "{:15s}".format(query_server))  # IP of DNS server
                    for query in queries_liste[ip][query_server]:
                        msg = address_contained(query)  # decoded string
                        if (msg is not ""):
                            global lst
                            if "size=" in msg:
                                global list_len
                                list_len = int(msg.split("size=")[-1])

                            lst.append(msg)
                        print(" " * 36 + "{:19s} {}".format(str(queries_liste[ip][query_server][query]),
                                                            query))  # Count DNS request | DNS


if __name__ == '__main__':
    lst = list()
    list_len=0
    #   write_to_file(lst)
    sniff(filter='udp port 53', store=0, prn=process, stop_filter=stopfilter)
    write_to_file(lst)