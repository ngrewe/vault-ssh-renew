from urllib.parse import ParseResult, urlparse

from click import ParamType


class URLParameterType(ParamType):

    name = "URL"

    def convert(self, value, param, ctx):
        if isinstance(value, ParseResult):
            return value
        try:
            return urlparse(value)
        except ValueError:
            self.fail("Invalid URL")
