from enum import Enum


class HTTPAwareEntity:

    class FailReason(Enum):
        CONNECTION_FAILED = "CONNECTION_FAILED"
        CONNECTION_TIMED_OUT = "CONNECTION_TIMED_OUT"
        HTTP504_GATEWAY_TIME_OUT = "HTTP504_GATEWAY_TIME_OUT"

    def __init__(self, url):
        self.securityHeaders = []
        self.url =  url
        self.failReason = None
        self.isSecureURL = False

class HTTPHeader:
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __str__(self):
        return self.name + ":"+self.value