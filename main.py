from socket import socket, AF_INET, SOCK_DGRAM, timeout
from dnsUtils import DNSUtils
from conf import Config
from cache import Cache

def _configure_server(config):
    server = socket(AF_INET, SOCK_DGRAM)
    server.settimeout(2)
    server.bind(config.local_server_address)
    return server

def receive_request(server, config):
    try:
        return server.recvfrom(config.buffer_size)
    except timeout:
        return receive_request(server, config)
    except Exception as e:
        server.close()
        print(e)
        exit()

def handle_request(data):
    return DNSUtils.parse(data)

def main():
    global server
    config = Config()
    cache = Cache.from_dump(config.cache_dump)
    try:
        while True:
            data, address = receive_request(server, config)
            response = handle_request(data)
            response, address = response.get_a().rdata, response.get_q().get_qname()
            print(response, address)
            server = socket(AF_INET, SOCK_DGRAM)
            server.bind(config.forwarder_address(Cache))
            server.sendto(str.encode(response), config.forwarder_address(Cache))
    except (KeyboardInterrupt, SystemExit):
        cache.dump_to_file(config.cache_dump)

if __name__ == '__main__':
    main()