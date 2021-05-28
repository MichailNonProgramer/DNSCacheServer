from decimal import Decimal
from time import time
import pickle

from dnsUtils import DNSQuestion
import conf

class Cache:
    def __init__(self):
        self._cache = {}
        self._time = {}
        self._record_type = {}

    def add(self, tup: tuple[str, str], record: DNSQuestion, record_type: str):
        self._cache[tup] = record
        self._record_type[tup] = record_type
        print(tup[0])
        self._time[tup] = conf.TTL + time()

    def _clean(self):
        names = list(self._cache.keys())
        for record in names:
            if Decimal(self._time[record]) < Decimal(time()):
                self._cache.pop(record)
                self._time.pop(record)

    @staticmethod
    def from_dump(filename: str) -> 'Cache':
        try:
            with open(filename, 'rb') as dump:
                cache = pickle.load(dump)
            print('Get saved cache.')
            return cache
        except EOFError:
            print('No cache.')
            return Cache()

    def dump_to_file(self, filename: str):
        with open(filename, 'wb+') as dump:
            pickle.dump(self, dump)