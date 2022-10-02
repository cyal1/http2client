"""
https://python-hyper.org/projects/h2/en/stable/plain-sockets-example.html
plain_sockets_client.py
~~~~~~~~~~~~~~~~~~~~~~~

Just enough code to send a GET request via h2 to an HTTP/2 server and receive a response body.
This is *not* a complete production-ready HTTP/2 client!
"""
import logging
import socket
import ssl
import h2.connection
import h2.events
from urllib3.util import parse_url
from h2.connection import H2Connection,H2Stream
from h2.events import (
    ResponseReceived, DataReceived, StreamEnded, StreamReset,
    SettingsAcknowledged,
)


def _new_track_content_length(self, length, end_stream):
    """
    Update the expected content length in response to data being received.
    Validates that the appropriate amount of data is sent. Always updates
    the received data, but only validates the length against the
    content-length header if one was sent.

    :param length: The length of the body chunk received.
    :param end_stream: If this is the last body chunk received.
    """
    self._actual_content_length += length
    actual = self._actual_content_length
    expected = self._expected_content_length

    if expected is not None:
        if expected < actual:
            logging.warn(f"InvalidBodyLengthError(expected: {expected}, actual: {actual})")
            return
            # raise InvalidBodyLengthError(expected, actual)

        if end_stream and expected != actual:
            logging.warn(f"InvalidBodyLengthError(expected: {expected}, actual: {actual})")
            return
            # raise InvalidBodyLengthError(expected, actual)
H2Stream._track_content_length = _new_track_content_length


class HttpStruct:
    _stream_id: int
    _headers: list = None
    _data: bytes = b''

    def __init__(self, stream_id: int):
        self._stream_id = stream_id

    def getHeaders(self):
        return self._headers

    def getData(self):
        return self._data

    def getStreamId(self):
        return self._stream_id

    def _setData(self, data):
        self._data = data

    def _setHeaders(self, headers):
        self._headers = headers

    def __str__(self) -> str:
        return f"<HttpStruct>{dict({'stream_id': str(self._stream_id), 'headers': self._headers, 'data': self._data})}"

    def raw_resp(self) -> bytes:
        return b"\r\n".join([b': '.join(header) for header in self.getHeaders()]) + b"\r\n" + self.getData()

    def getStatusCode(self):
        if not self.getHeaders():
            return None
        return self.getHeaders()[0][1].decode()

    def getContentLength(self) -> int:
        return len(self.getData())


def establish_tcp_connection(host, port, timeout=15):
    """
    This function establishes a client-side TCP connection. How it works isn't
    very important to this example. For the purpose of this example we connect
    to localhost.
    """
    socket.setdefaulttimeout(timeout)
    return socket.create_connection((host, port))


def get_http2_ssl_context():
    """
    This function creates an SSLContext object that is suitably configured for
    HTTP/2. If you're working with Python TLS directly, you'll want to do the
    exact same setup as this function does.
    """
    # Get the basic context from the standard library.
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    # RFC 7540 Section 9.2: Implementations of HTTP/2 MUST use TLS version 1.2
    # or higher. Disable TLS 1.1 and lower.
    ctx.options |= (
            ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )

    # RFC 7540 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
    # compression.
    ctx.options |= ssl.OP_NO_COMPRESSION

    # RFC 7540 Section 9.2.2: "deployments of HTTP/2 that use TLS 1.2 MUST
    # support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256". In practice, the
    # blocklist defined in this section allows only the AES GCM and ChaCha20
    # cipher suites with ephemeral key negotiation.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")

    # We want to negotiate using NPN and ALPN. ALPN is mandatory, but NPN may
    # be absent, so allow that. This setup allows for negotiation of HTTP/1.1.
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    try:
        ctx.set_npn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    return ctx


def negotiate_tls(tcp_conn, context, host, http2_prior_knowledge=False):
    """
    Given an established TCP connection and a HTTP/2-appropriate TLS context,
    this function:

    1. wraps TLS around the TCP connection.
    2. confirms that HTTP/2 was negotiated and, if it was not, throws an error.
    """
    # Note that SNI is mandatory for HTTP/2, so you *must* pass the
    # server_hostname argument.
    tls_conn = context.wrap_socket(tcp_conn, server_hostname=host)

    # Always prefer the result from ALPN to that from NPN.
    # You can only check what protocol was negotiated once the handshake is
    # complete.

    if not http2_prior_knowledge:
        negotiated_protocol = tls_conn.selected_alpn_protocol()
        if negotiated_protocol is None:
            negotiated_protocol = tls_conn.selected_npn_protocol()
        if negotiated_protocol != "h2":
            raise RuntimeError(
                "Server didn't negotiate HTTP/2 or Server not supports HTTP/2. If you know the Server supports HTTP/2, set http2_prior_knowledge=True to skip negotiate.")

    return tls_conn


def url_analyze(url) -> tuple:
    u = parse_url(url.strip())
    host = u.host
    port = u.port if u.port is not None else 443
    path = u.request_uri if u.request_uri is not None else '/'
    return u.scheme, host, port, path


def request(method: str, url: str, headers: list = None, data: bytes = None,
            http2_prior_knowledge=False,
            normalize=True,
            validate=True,
            timeout: int = 10) -> HttpStruct:
    _, host, port, path = url_analyze(url.strip())

    resp_seq = {}

    if headers is None:
        headers = [
            (':method', method),
            (':path', path),
            (':authority', host),
            (':scheme', 'https'),
        ]
        if data is not None:
            headers.append(("content-length", str(len(data))))

    # Step 1: Set up your TLS context.
    context = get_http2_ssl_context()
    # context.verify_mode = ssl.CERT_NONE

    # Step 2: Create a TCP connection.
    connection = establish_tcp_connection(host, port, timeout=timeout)

    # Step 3: Wrap the connection in TLS and validate that we negotiated HTTP/2
    tls_connection = negotiate_tls(connection, context, host, http2_prior_knowledge=http2_prior_knowledge)

    # Step 4: Create a client-side H2 connection.
    config = h2.connection.H2Configuration()
    config.validate_outbound_headers = validate
    config.normalize_outbound_headers = normalize
    config.validate_inbound_headers = validate
    config.normalize_inbound_headers = normalize
    http2_connection = H2Connection(config=config)

    # Step 5: Initiate the connection
    http2_connection.initiate_connection()

    if data is None:
        http2_connection.send_headers(stream_id=1, headers=headers, end_stream=True)
        resp_seq[1] = HttpStruct(1)
    else:
        http2_connection.send_headers(stream_id=1, headers=headers)
        http2_connection.send_data(stream_id=1, data=data, end_stream=True)
        resp_seq[1] = HttpStruct(1)
    tls_connection.sendall(http2_connection.data_to_send())
    response_stream_ended = False

    while not response_stream_ended:
        # read raw data from the socket
        # print("before receive data")
        recv_data = tls_connection.recv(65536 * 1024)
        # print("after receive data before")

        if not recv_data:
            raise RuntimeError(f"{url} <StreamId: 1>: no data receive")

        # feed raw data into h2, and process resulting events
        events = http2_connection.receive_data(recv_data)
        for event in events:
            # print(event)
            if isinstance(event, ResponseReceived):
                # resp_headers = event.headers
                resp_seq[event.stream_id]._setHeaders(event.headers)

            elif isinstance(event, DataReceived):
                # update flow control so the server doesn't starve us
                http2_connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                # more response body data received
                # resp_body += event.data
                resp_seq[event.stream_id]._setData(resp_seq[event.stream_id].getData() + event.data)
            elif isinstance(event, StreamEnded):
                # response body completed, let's exit the loop
                response_stream_ended = True
                break
            elif isinstance(event, SettingsAcknowledged):
                """
                Called when the remote party ACKs our settings. We send a SETTINGS
                frame as part of the preamble, so if we want to be very polite we can
                wait until the ACK for that frame comes before we start sending our
                request.
                """
                pass

            elif isinstance(event, StreamReset):
                # logging.error("%s <StreamId: %d>: %s" % (url, event.stream_id, event.error_code))
                http2_connection.close_connection()
                tls_connection.close()
                raise RuntimeError(f"{url} <StreamId: {event.stream_id}>: StreamReset, {str(event.error_code)}")
                # return resp_seq[event.stream_id]

        # send any pending data to the server
        tls_connection.sendall(http2_connection.data_to_send())

    # tell the server we are closing the h2 connection
    http2_connection.close_connection()
    tls_connection.sendall(http2_connection.data_to_send())

    # close the socket
    tls_connection.close()

    # print(resp_body)
    return resp_seq[1]


def get(url: str, headers: list = None, data: bytes = None,
        http2_prior_knowledge=False,
        normalize=True,
        validate=True,
        timeout: int = 10):
    return request("GET", url, headers=headers, data=data, http2_prior_knowledge=http2_prior_knowledge,
                   normalize=normalize, validate=validate, timeout=timeout)


def post(url: str, headers: list = None, data: bytes = None,
         http2_prior_knowledge=False,
         normalize=True,
         validate=True,
         timeout: int = 10):
    return request("POST", url, headers=headers, data=data, http2_prior_knowledge=http2_prior_knowledge,
                   normalize=normalize, validate=validate, timeout=timeout)


class Session:
    # def __del__(self):
    #     if self.__connection.fileno() != -1:
    #         self.close()

    def __init__(self, host: str, port: int, config: h2.connection.H2Configuration = h2.connection.H2Configuration(),
                 http2_prior_knowledge: bool = False,
                 timeout: int = 10):
        # Step 1: Set up your TLS context.
        context = get_http2_ssl_context()
        # context.verify_mode = ssl.CERT_NONE

        # Step 2: Create a TCP connection.
        # socket.setdefaulttimeout(timeout)
        # return socket.create_connection((host, port))
        self.__stream_id = -1
        self.__connection = establish_tcp_connection(host, port, timeout=timeout)

        # Step 3: Wrap the connection in TLS and validate that we negotiated HTTP/2
        self.__tls_connection = negotiate_tls(self.__connection, context, host,
                                              http2_prior_knowledge=http2_prior_knowledge)

        # Step 4: Create a client-side H2 connection.
        self.__http2_connection = H2Connection(config=config)

        # Step 5: Initiate the connection
        self.__http2_connection.initiate_connection()

    def close(self):
        # tell the server we are closing the h2 connection
        self.__http2_connection.close_connection()
        # self.__tls_connection.sendall(self.__http2_connection.data_to_send())

        # close the socket
        self.__tls_connection.close()

    def request(self, method: str, url: str, headers: list = None, data: bytes = None,
                timeout: int = 15) -> HttpStruct:
        self.__stream_id += 2
        if not self.__tls_connection.session:
            raise RuntimeError(
                f"{url} <StreamId: {self.__stream_id}>: Connection closed")
        # self.__connection.settimeout(timeout) # not work
        _, host, port, path = url_analyze(url.strip())

        if headers is None:
            headers = [
                (':method', method),
                (':path', path),
                (':authority', host),
                (':scheme', 'https'),
            ]
            if data is not None:
                headers.append(("content-length", str(len(data))))
        resp_seq = {}

        if data is None:
            self.__http2_connection.send_headers(stream_id=self.__stream_id, headers=headers, end_stream=True)
            resp_seq[self.__stream_id] = HttpStruct(self.__stream_id)
        else:
            self.__http2_connection.send_headers(stream_id=self.__stream_id, headers=headers)
            self.__http2_connection.send_data(stream_id=self.__stream_id, data=data, end_stream=True)
            resp_seq[self.__stream_id] = HttpStruct(self.__stream_id)
        self.__tls_connection.sendall(self.__http2_connection.data_to_send())

        response_stream_ended = False

        while not response_stream_ended:
            # read raw data from the socket
            # print("before receive data")
            recv_data = self.__tls_connection.recv(65536 * 1024)
            # print("after receive data before")

            if not recv_data:
                self.close()
                raise RuntimeError(f"{url} <StreamId: {self.__stream_id}>: no data receive")
                # break

            # feed raw data into h2, and process resulting events
            events = self.__http2_connection.receive_data(recv_data)
            for event in events:
                # print(event)
                if isinstance(event, ResponseReceived):
                    # resp_headers = event.headers
                    resp_seq[event.stream_id]._setHeaders(event.headers)

                elif isinstance(event, DataReceived):
                    # update flow control so the server doesn't starve us
                    self.__http2_connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    # more response body data received
                    # resp_body += event.data
                    resp_seq[event.stream_id]._setData(resp_seq[event.stream_id].getData() + event.data)
                elif isinstance(event, StreamEnded):
                    # response body completed, let's exit the loop
                    response_stream_ended = True
                    break
                elif isinstance(event, SettingsAcknowledged):
                    """
                    Called when the remote party ACKs our settings. We send a SETTINGS
                    frame as part of the preamble, so if we want to be very polite we can
                    wait until the ACK for that frame comes before we start sending our
                    request.
                    """
                    pass

                elif isinstance(event, StreamReset):
                    # print(headers, data)
                    self.close()
                    raise RuntimeError(f"{url} <StreamId: {event.stream_id}>: StreamReset, {str(event.error_code)}")
                    # self.close()
                    # return resp_seq[event.stream_id]
                    # print(event.error_code)
                    # raise RuntimeError("Stream reset: %d" % event.error_code)

            # send any pending data to the server
            self.__tls_connection.sendall(self.__http2_connection.data_to_send())

        # print(resp_body)
        return resp_seq[self.__stream_id]

    def get(self, url, data: bytes = None, headers: list = None, timeout: int = 10):
        return self.request("GET", url, data=data, headers=headers, timeout=timeout)

    def post(self, url, data: bytes = None, headers: list = None, timeout: int = 10):
        return self.request("POST", url, data=data, headers=headers, timeout=timeout)
