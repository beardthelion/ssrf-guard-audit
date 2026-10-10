# Synthetic fixture: a network sink inside a function with no
# caller-shaped input (no URL-named parameter or field read, no
# registration shape), next to a registered entry point with no sink. The
# sink must land on the coverage "outside recognized entries" line rather
# than reading as an empty or a guarded scan.
# Not imported or executed by pytest; scanned as data only.

import requests


class Server:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


server = Server()


def fetch_helper(arg: str) -> str:
    return requests.get(arg).text


@server.tool()
def describe(name: str) -> str:
    return f"describes {name}"
