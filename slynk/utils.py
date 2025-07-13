import ipaddress
import socket
import struct
import asyncio
import functools
import contextvars

async def to_thread(func, /, *args, **kwargs):
    """Asynchronously run function *func* in a separate thread.

    Any *args and **kwargs supplied for this function are directly passed
    to *func*. Also, the current :class:`contextvars.Context` is propagated,
    allowing context variables from the main thread to be accessed in the
    separate thread.

    Return a coroutine that can be awaited to get the eventual result of *func*.
    """
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    func_call = functools.partial(ctx.run, func, *args, **kwargs)
    return await loop.run_in_executor(None, func_call)

def ip_to_binary_prefix(ip_or_network):
    try:
        network = ipaddress.ip_network(ip_or_network, strict=False)
        network_address = network.network_address
        prefix_length = network.prefixlen
        if isinstance(network_address, ipaddress.IPv4Address):
            binary_network = bin(int(network_address))[2:].zfill(32)
        elif isinstance(network_address, ipaddress.IPv6Address):
            binary_network = bin(int(network_address))[2:].zfill(128)
        binary_prefix = binary_network[:prefix_length]
        return binary_prefix
    except ValueError:
        try:
            ip = ipaddress.ip_address(ip_or_network)
            if isinstance(ip, ipaddress.IPv4Address):
                binary_ip = bin(int(ip))[2:].zfill(32)
                binary_prefix = binary_ip[:32]
            elif isinstance(ip, ipaddress.IPv6Address):
                binary_ip = bin(int(ip))[2:].zfill(128)
                binary_prefix = binary_ip[:128]
            return binary_prefix
        except ValueError:
            raise ValueError(
                f"{ip_or_network} is not a valid IP address or network"
            )

def set_ttl(sock, ttl):
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

def check_ttl(ip, port, ttl):
    from .logger_with_context import logger
    logger = logger.getChild("utils")
    try:
        if ':' in ip:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_ttl(sock, ttl)
        sock.settimeout(0.5)
        sock.connect((ip, port))
        sock.send(b"0")
        return True
    except Exception as e:
        logger.error(
            'TTL %d for %s:%d failed due to %s.', ttl, ip, port, repr(e)
        )
        return False
    finally:
        sock.close()

def get_ttl(ip, port):
    from .logger_with_context import logger
    logger = logger.getChild("utils")
    l = 1
    r = 128
    ans = -1
    while l <= r:
        mid = (l + r) // 2
        val = check_ttl(ip, port, mid)
        logger.debug("%d %d %d %d %d", l, r, mid, ans, val)
        if val:
            ans = mid
            r = mid - 1
        else:
            l = mid + 1

    logger.info("TTL %d is reachable on %s:%d.", ans, ip, port)
    return ans

def is_ip_address(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def extract_sni(data):
    """
    extract sni
    data: the tls data.
    """
    # 解析TLS记录
    content_type, _, _, length = struct.unpack(">BBBH", data[:5])
    if content_type != 0x16:  # 0x16表示TLS Handshake
        raise ValueError("Not a TLS Handshake message")
    handshake_data = data[5 : 5 + length]

    # 解析握手消息头
    handshake_type, tmp, length = struct.unpack(">BBH", handshake_data[:4])
    length = tmp * 64 + length
    if handshake_type != 0x01:  # 0x01表示Client Hello
        raise ValueError("Not a Client Hello message")
    client_hello_data = handshake_data[4 : 4 + length]

    # 解析Client Hello消息
    _, _, _, session_id_length = struct.unpack(">BB32sB", client_hello_data[:35])
    cipher_suites_length = struct.unpack(
        ">H", client_hello_data[35 + session_id_length : 35 + session_id_length + 2]
    )[0]
    compression_methods_length = struct.unpack(
        ">B",
        client_hello_data[
            35
            + session_id_length
            + 2
            + cipher_suites_length : 35
            + session_id_length
            + 2
            + cipher_suites_length
            + 1
        ],
    )[0]

    # 定位扩展部分
    extensions_offset = (
        35
        + session_id_length
        + 2
        + cipher_suites_length
        + 1
        + compression_methods_length
    )
    extensions_length = struct.unpack(
        ">H", client_hello_data[extensions_offset : extensions_offset + 2]
    )[0]
    extensions_data = client_hello_data[
        extensions_offset + 2 : extensions_offset + 2 + extensions_length
    ]

    offset = 0
    while offset < extensions_length:
        extension_type, extension_length = struct.unpack(
            ">HH", extensions_data[offset : offset + 4]
        )
        if extension_type == 0x0000:  # SNI扩展的类型是0x0000
            sni_extension = extensions_data[offset + 4 : offset + 4 + extension_length]
            # 解析SNI扩展
            list_length = struct.unpack(">H", sni_extension[:2])[0]
            if list_length != 0:
                name_type, name_length = struct.unpack(">BH", sni_extension[2:5])
                if name_type == 0:  # 域名类型
                    sni = sni_extension[5 : 5 + name_length]
                    return sni
        offset += 4 + extension_length
    return None

def check_key_share(data):
    '''
    Validate the existence of "key_share" in ClientHello.
    '''
    try:
        if len(data) < 5: # Not long enough
            return 0, None

        # Parse TLS record layer header: 1-byte type, 2-byte version, 2-byte length.
        record_type, record_version, record_length = struct.unpack('!BHH', data[:5])

        # Check if it is a Handshake (type 22) and data length is sufficient.
        if record_type != 22 or len(data) < 5 + record_length:
            return 0, None

        # Extract Handshake protocol data (excluding record layer header).
        handshake_data = data[5:5 + record_length]
        if len(handshake_data) < 4:  # Handshake header must be at least 4 bytes.
            return 0, None

         # Parse Handshake header: 1-byte type, 3-byte length.
        handshake_type = handshake_data[0]
        handshake_len = int.from_bytes(handshake_data[1:4], 'big')

        # Verify it is a ClientHello (type 1) and length matches.
        if handshake_type != 1 or len(handshake_data) < 4 + handshake_len:
            return 0, protocol_version

        # Extract ClientHello body (excluding Handshake header).
        hello_body = handshake_data[4:4 + handshake_len]
        offset = 0

        # Skip fixed fields: protocol version (2 bytes) + random (32 bytes).
        if len(hello_body) < 34:
            return 0, protocol_version
        protocol_version = hello_body[:2]
        offset += 34

        # Parse and skip session ID.
        if offset >= len(hello_body):
            return 0, protocol_version
        session_id_len = hello_body[offset]
        offset += 1
        if offset + session_id_len > len(hello_body):
            return 0, protocol_version
        offset += session_id_len

        # Parse and skip cipher suites.
        if offset + 2 > len(hello_body):
            return 0, protocol_version
        cipher_suites_len = int.from_bytes(hello_body[offset:offset + 2], 'big')
        offset += 2
        if offset + cipher_suites_len > len(hello_body):
            return 0, protocol_version
        offset += cipher_suites_len

        # Parse and skip compression methods.
        if offset >= len(hello_body):
            return 0, protocol_version
        compression_len = hello_body[offset]
        offset += 1
        if offset + compression_len > len(hello_body):
            return 0, protocol_version
        offset += compression_len

        # Check if there are extensions length.
        if offset == len(hello_body):
            return -1  # No extensions.
        if offset + 2 > len(hello_body):
            return 0, protocol_version

        # Parse total extensions length.
        extensions_len = int.from_bytes(hello_body[offset:offset + 2], 'big')
        offset += 2
        if offset + extensions_len > len(hello_body):
            return 0, protocol_version

        # Traverse through extensions.
        end_ext = offset + extensions_len
        while offset < end_ext:
            # Each extension must have at least a 4-byte header.
            if offset + 4 > end_ext:
                return 0, protocol_version
            ext_type = int.from_bytes(hello_body[offset:offset + 2], 'big')
            ext_len = value = int.from_bytes(
                hello_body[offset + 2:offset+ 4 ], 'big'
            )
            offset += 4

            # Check for `key_share` (extension type 51).
            if ext_type == 51:
                return 1, protocol_version

            # Skip over extension data.
            offset += ext_len
            if offset > end_ext:
                return 0, protocol_version

        return -1, protocol_version

    except Exception as e:
        from .logger_with_context import logger
        logger = logger.getChild("utils")
        logger.debug('While checking key_share: %s', repr(e))
        return 0, None

async def send_tls_alert(writer, client_version):
    '''Send fake TLS Alert message to the client'''
    if client_version:
        alert_type = 0x15
        version_major, version_minor = client_version
        alert_level = 0x02  # Fatal level
        alert_description = 0x46  # protocol_version(70)
        alert_payload = bytes((alert_level, alert_description))
        record_header = struct.pack(
            ">BHH",
            alert_type,
            (version_major << 8) | version_minor,
            len(alert_payload)
        )
        writer.write(record_header + alert_payload)
        await writer.drain()
