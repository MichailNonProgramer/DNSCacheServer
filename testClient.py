import binascii
import socket


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
    finally:
        sock.close()
    return binascii.hexlify(b'').decode("Windows-1251")


def format_hex(hex):
    octets = [hex[i:i + 2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i + 2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)


swebRu = "73 77 65 62 2e 72 75"

message = f"AA AA 01 00 00 01 00 00 00 00 00 00 " \
          f"07 {swebRu} 00 00 01 00 01"

response = send_udp_message(message, "127.0.0.1", 53)
print(format_hex(response))