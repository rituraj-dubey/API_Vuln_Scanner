from mitmproxy import http, ctx

class LogTraffic:
    def __init__(self):
        self.target_domain = None

    def load(self, loader):
        loader.add_option(
            "target_domain", str, "", "Target domain to log"
        )

    def configure(self, updated):
        if "target_domain" in updated:
            self.target_domain = ctx.options.target_domain
            print(f"Configured target domain: {self.target_domain}")

    def request(self, flow: http.HTTPFlow) -> None:
        if self.target_domain in flow.request.pretty_host:
            with open("requests.log", "a") as log:
                log.write(f"Request: {flow.request.method} {flow.request.url}\n")
                log.write(f"Headers: {flow.request.headers}\n")
                log.write(f"Content: {flow.request.content}\n\n")

addons = [
    LogTraffic()
]


