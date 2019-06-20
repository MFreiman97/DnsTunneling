import base64
from os import system

from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sniff

queries_liste = {}  # Global variable
quiet = False
databaseConn = None
databaseCursor = None
msgs = set()
msgs_count = 0
ind_delim = ' #index '
fn_delim = ' #FILENAME#'


def decode_from_base32(enc_mes):
    enc_mes = enc_mes.replace('.', '')
    b = bytes(enc_mes, 'utf-8')
    mes = base64.b32decode(b.upper())
    b = str(mes, 'utf-8')
    return b


def write_to_file(client_texts):
    file_name = ''.join({c.split(fn_delim)[0] for c in client_texts if fn_delim in c})
    client_texts = {int(l.split(ind_delim)[1][:-1]): l.split(ind_delim)[0] for l in client_texts if ind_delim in l}
    file_name = file_name.split('/')[-1]
    print(file_name)
    with open(file_name, mode="w+", encoding='utf-8') as file:
        for key in sorted(client_texts):
            file.write(client_texts[key])


def get_message(x: bytes):
    try:
        x = str(x, 'utf-8')
    except TypeError:
        return ''
    if "legit-domain.demo" in x:
        x = x.split("legit-domain.demo")[0]
        return decode_from_base32(x)
    return ''


def stopfilter(x):
    global msgs
    global msgs_count
    if len(msgs) == msgs_count and msgs_count > 0:
        return True
    else:
        return False


def extract_messages(queries):
    for query in queries:
        msg = get_message(query)
        if msg is not '':
            global msgs
            msgs.add(msg)
            if "size=" in msg:
                global msgs_count
                msgs_count = int(msg.split("size=")[-1])


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
            system('clear')
            print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))
            for ip in queries_liste:
                print("{:15s}".format(ip))  # IP source
                for query_server in queries_liste[ip]:
                    print(" " * 18 + "{:15s}".format(query_server))  # IP of DNS server
                    queries = queries_liste[ip][query_server]
                    extract_messages(queries)
                    for query in queries:
                        print(" " * 36 + "{:19s} {}".format(str(queries_liste[ip][query_server][query]),
                                                            query))  # Count DNS request | DNS


def main():
    sniff(filter='udp port 53', store=0, prn=process, stop_filter=stopfilter)
    write_to_file(msgs)
    print("File Was Created")


if __name__ == '__main__':
    main()
