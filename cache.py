from dataclasses import dataclass

from httpmsg import HttpMsg
from logger import LoggerMixin


@dataclass
class CacheEntry:
    url: str
    response: bytes

class Cache(LoggerMixin):
    cache: dict[int,CacheEntry] = {}

    def __init__(self, config: dict):
        super().__init__()
        self.cache = {}
        self.set_logging(config)

    def add(self, request: HttpMsg, response: HttpMsg):
        key = self.getKey(request)
        self.cache[key] = CacheEntry(request.absolute_url, response.raw)
        self.info('', f'Added {request.absolute_url} to cache')

    def get(self, request: HttpMsg):
        key = self.getKey(request)
        response = self.cache.get(key,None)
        if response:
            result = 'Got'
            url = response.url
            data = response.response
        else:
            result = 'Missed'
            url = request.absolute_url
            data = None
        self.info('', f'{result} {url}')
        return data

    def getKey(self, request) -> int:
        return hash(request.absolute_url)