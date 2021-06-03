import pickle
from response import Response
from utils import get_current_seconds

class Cache:

    def __init__(self):
        self.cache = dict()
        self.cache[("1.0.0.127.in-addr.arpa", "000c")] = [Response("000c", "03646e73056c6f63616c00", "100")]
        self.load_data()
        self.prev_time = get_current_seconds()
        print(self.cache)

    def clear_cache(self):
        current_time = get_current_seconds()
        if current_time - self.prev_time >= 120:
            keys_to_delete = []
            for k, v in self.cache.items():
                for item in v:
                    if item.valid_till <= current_time:
                        del item
                if len(v) == 0:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del self.cache[k]
            self.prev_time = get_current_seconds()

        # сохранение обновленного кэша
        with open("cache", "wb+") as f:
            pickle.dump(self.cache, f)

    def get_data(self):
        return self.cache

    def load_data(self):
        try:
            with open("cache", "rb") as f:
                self.cache = pickle.load(f)
        except:
            print("cache file not found")
