import base64


#class Server

def decode_from_base32(enc_mes):  #
    enc_mes = enc_mes.replace('.', '')
    b = bytes(enc_mes, 'utf-8')
    mes = base64.b32decode(b)

    b = str(mes, 'utf-8')
    return b