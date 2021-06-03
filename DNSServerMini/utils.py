import binascii
import socket
import time

def get_current_seconds():
    return int(round(time.time()))


def decimal_to_hex(n):
    return hex(n)[2:]

def get_name(r, start_name_index=24):
    name = []
    offset = 0
    while True:
        index = start_name_index + offset

        # длина метки, либо ссылка
        raw = r[index:index + 4]

        # проверка на то, что это ссылка (первые 2 бита = 11)
        if int(raw, 16) >= 49152:
            link = str(bin(int(raw, 16)))[2:]

            link = int(link[2:], 2) * 2

            rest, offset = get_name(r, link)
            name.append(rest)
            name.append(".")
            break

        length = int(r[index:index + 2], 16)

        # Если долши до 00, то останавливаемся
        if length == 0:
            break

        i = 2
        while i <= length * 2:
            decoded = chr(int(r[index + i:index + i + 2], 16))
            name.append(decoded)
            i += 2

        name.append(".")
        offset += length * 2 + 2

    name = "".join(name[:-1])

    return name, offset

def send_udp_message(msg, address, port):
    msg = msg.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    print("sender")
    try:
        sock.sendto(binascii.unhexlify(msg), server_address)
        response, _ = sock.recvfrom(4096)
    except:
        return None

    print(response)
    print(binascii.hexlify(response).decode("utf-8"))
    return binascii.hexlify(response).decode("utf-8")