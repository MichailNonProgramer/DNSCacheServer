import pickle
from socket import *
from response import Response
import binascii
from cache import Cache
from request import Request

from utils import get_name

QTYPE = {1: 'A', 2: 'NS', 12: 'PTR', 28: 'AAAA'}

class Server:
    def __init__(self, socket):
        self.socket = socket
        self.cache = Cache()

    def start(self):
        while True:
            try:
                received, addr = socket.recvfrom(1024)
                received = binascii.hexlify(received).decode("utf-8")
                req = Request()
                response = self.parse_response(req.parse_request(received, self.cache.get_data()), self.cache.get_data())
                if response is not None:
                    socket.sendto(binascii.unhexlify(response), addr)
                print(self.cache.get_data())
                self.cache.clear_cache()
                socket.dup()
            except:
                print("Exeption")
                pass

    def extract_name(self, r, ind):
        link = str(bin(int(r[ind:ind+4], 16)))[2:]
        link = int(link[2:], 2) * 2
        res, _ = get_name(r, link)
        print(res)
        return res

    def parse_response(self, r, cache):
        print(r)
        if r is None:
            return None

        header = r[0:24]
        question = r[24:]

        name, offset = get_name(r)

        t = question[offset - 8: offset - 4]

        dot_count = name.count(".")
        char_count = len(name) - dot_count
        question_len = char_count * 2 + (dot_count + 2) * 2

        answer = r[24 + question_len + 8:]

        an_count = int(header[12:16], 16)
        ns_count = int(header[16:20], 16)
        ar_count = int(header[20:24], 16)

        counts = [an_count, ns_count, ar_count]

        rest = answer
        for count in counts:
            answers = []
            print(count)
            prev_n = name
            n = name

            for i in range(count):
                n = self.extract_name(r, r.index(rest))
                t = rest[4:8]
                ttl = rest[12:20]
                data_len = rest[20:24]

                data_length = int(data_len, 16) * 2
                data = rest[24:24 + data_length]

                link = str(bin(int(data[-4:], 16)))[2:]
                if t == "0002" and data[-2:] != "00" and link[:2] == "11":
                    link = int(link[2:], 2) * 2
                    _, offset = get_name(r[link:], 0)
                    ending = r[link:link+offset] + "00"
                    data = data[:-4] + ending

                ans = Response(t, data, ttl)

                rest = rest[24 + data_length:]

                if n != prev_n:
                    cache[(n, QTYPE.get(int(t, 16)))] = [ans]
                    answers = []
                else:
                    answers.append(ans)
                print(answers, "ans")
                prev_n = n

            if len(answers) != 0:
                cache[(n, QTYPE.get(int(t, 16)))] = answers

        # сохранение обновленного кэша
        with open("cache", "wb+") as f:
            pickle.dump(cache, f)

        return r

if __name__ == '__main__':
    host = 'localhost'
    port = 53
    socket = socket(AF_INET, SOCK_DGRAM)
    socket.bind((host, port))
    server = Server(socket)
    server.start()