# http2client
A simple HTTP/2 client for Cyber Security

Useage:
```python
import h2.connection
import http2client
import json

config = h2.connection.H2Configuration()
config.validate_outbound_headers = False
config.validate_inbound_headers = False
config.normalize_outbound_headers = False
s = http2client.Session("httpbin.org", 443, config=config, http2_prior_knowledge=True)

body = b'0\r\n\r\nGET /404 HTTP/1.1\r\nx: x'

headers = [
    (':method', 'POST'),
    (':path', "/anything"),
    (':authority', "httpbin.org"),
    (':scheme', 'https'),
    # ('User-Agent', 'testet\r\nTransfer-Encoding: chunked'),
    ('content-length', len(body)),
]

# If the headers is set, the url will be ignored
stream1 = s.post("https://httpbin.org", headers=headers, data=body)  
stream2 = s.get("https://httpbin.org/anything")
print(json.loads(stream1.getData()))
print(json.loads(stream2.getData()))


resp = http2client.request("GET", "https://httpbin.org/anything",
                           http2_prior_knowledge=True,
                           normalize=False,
                           validate=False,
                           timeout=10
                           )
print(resp.getHeaders())
print(json.loads(resp.getData()))

```