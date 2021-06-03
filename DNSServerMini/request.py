from utils import decimal_to_hex, get_name, send_udp_message

QTYPE = {1: 'A', 2: 'NS', 12: 'PTR', 28: 'AAAA'}

class Request:

    def get_all_responses(self, arr):
        res = []
        for item in arr:
            content, is_valid = item.form_response()
            if is_valid:
                res.append(content)
        return "".join(res), len(res)

    def parse_request(self, request, cache):
        header = request[0:24]
        question = request[24:]

        name, _ = get_name(request)

        t = question[-8: -4]

        # проверяем наличие записей в кэше
        if (name, t) in cache:
            content, count = self.get_all_responses(cache[(name, t)])

            if count != 0:
                if QTYPE.get(int(t, 16)) == "AAAA":
                    _id = header[0:16]
                else:
                    _id = header[0:4]
                flags = "8180"
                qd_count = header[8:12]
                an_count = decimal_to_hex(count).rjust(4, '0')
                ns_count = header[16:20]
                ar_count = header[20:24]
                new_header = _id + flags + qd_count + an_count + ns_count + ar_count
                print(f"name {name} type '{QTYPE.get(int(t, 16))}' record returned from cache")
                return new_header + question + content
        print(f"{name} type '{QTYPE.get(int(t, 16))}' ")
        return send_udp_message(request, "8.8.8.8", 53)