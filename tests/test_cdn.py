import json

from aliyun_cdn_guard.cdn import CdnGateway


class FakeClient:
    def __init__(self):
        self.request = None

    def batch_set_cdn_domain_config(self, request):
        self.request = request


def test_payload_sets_client_ip_mode_without_response_code():
    gateway = CdnGateway.__new__(CdnGateway)
    gateway.client = FakeClient()
    gateway.ip_acl_xfwd = "on"
    gateway.set_blacklist("cdn.example.com", {"203.0.113.2", "203.0.113.1"})
    functions = json.loads(gateway.client.request.functions)
    args = {item["argName"]: item["argValue"] for item in functions[0]["functionArgs"]}
    assert args == {"ip_list": "203.0.113.1,203.0.113.2", "ip_acl_xfwd": "on"}
    assert "customize_response_status_code" not in args
