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

def ip_to_binary_prefix(ip_or_network: str):
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

def check_ttl(ip: str, port: int, ttl: int) -> bool:
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

def get_ttl(ip: str, port: int) -> int:
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

def is_ip_address(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def extract_sni(data: bytes):
    if len(data) < 5:
        return None
    content_type = data[0]
    length = struct.unpack_from(">H", data, 3)[0]
    if content_type != 0x16 or len(data) < 5 + length:
        return None

    handshake_data = memoryview(data)[5:5 + length]
    if len(handshake_data) < 4:
        return None
    handshake_type = handshake_data[0]
    hello_length = (
        handshake_data[1] * 2 ** 16
        + struct.unpack_from(">H", handshake_data, 2)[0]
    )
    if handshake_type != 0x01 or len(handshake_data) < 4 + hello_length:
        return None

    point = 4
    if point + 34 > len(handshake_data):
        return None
    point += 34  # Skip protocol version and random number
    session_id_length = handshake_data[point]
    point += 1 + session_id_length
    if point + 2 > len(handshake_data):
        return None
    cipher_suites_length = struct.unpack_from(">H", handshake_data, point)[0]
    point += 2 + cipher_suites_length
    if point >= len(handshake_data):
        return None
    compression_methods_length = handshake_data[point]
    point += 1 + compression_methods_length

    if point + 2 > len(handshake_data):
        return None
    extensions_length = struct.unpack_from(">H", handshake_data, point)[0]
    point += 2
    end = point + extensions_length
    while point + 4 <= end:
        ext_type, ext_len = struct.unpack_from(">HH", handshake_data, point)
        point += 4
        if ext_type == 0x0000 and ext_len >= 5:  # SNI
            list_len = struct.unpack_from(">H", handshake_data, point)[0]
            if list_len >= 3:
                name_type = handshake_data[point + 2]
                if name_type == 0:
                    name_len = struct.unpack_from(
                        ">H", handshake_data, point + 3
                    )[0]
                    sni_start = point + 5
                    sni_end = sni_start + name_len
                    if sni_end <= point + ext_len:
                        return handshake_data[sni_start:sni_end].tobytes()
        point += ext_len
    return None

def check_key_share(data: bytes) -> tuple:
    '''
    Check if "key_share" extension exists in ClientHello. 
    Return (1/0/-1, protocol_version bytes or None)
        1: found key_share
        0: error or key_share not found
       -1: no extensions
    '''
    try:
        if len(data) < 5: # Not long enough
            return 0, None

        typ, ver, rec_len = struct.unpack_from('!BHH', data, 0)

        if typ != 22 or len(data) < 5 + rec_len:
            return 0, None

        handshake_data = memoryview(data)[5:5 + rec_len]
        hdsk_len =  len(handshake_data)
        if hdsk_len < 4:
            return 0, None

        handshake_type = handshake_data[0]
        handshake_len = int.from_bytes(handshake_data[1:4], 'big')

        if handshake_type != 1 or hdsk_len < 4 + handshake_len:
            return 0, None

        pos = 4
        if pos + 34 > hdsk_len:
            return 0, None
        protocol_version = handshake_data[pos:pos + 2].tobytes()
        pos += 34

        if pos >= hdsk_len:
            return 0, protocol_version
        sess_id_len = handshake_data[pos]
        pos += 1 + sess_id_len

        if pos + 2 > hdsk_len:
            return 0, protocol_version
        cipher_len = struct.unpack_from('!H', handshake_data, pos)[0]
        pos += 2 + cipher_len
        if pos >= hdsk_len:
            return 0, protocol_len
        comp_len = handshake_data[pos]
        pos += 1 + comp_len

        if pos == hdsk_len:
            return -1, protocol_version  # no extensions
        if pos + 2 > hdsk_len:
            return 0, protocol_version

        ext_len = struct.unpack_from('!H', handshake_data, pos)[0]
        pos += 2
        if pos + ext_len > hdsk_len:
            return 0, protocol_version

        end = pos + ext_len
        while pos + 4 <= end:
            ext_type, ext_data_len = struct.unpack_from(
                '!HH', handshake_data, pos
            )
            pos += 4
            if ext_type == 51:  # key_share
                return 1, protocol_version
            pos += ext_data_len
            if pos > end:
                return 0, protocol_version

        return -1, protocol_version

    except Exception as e:
        from .logger_with_context import logger
        logger = logger.getChild("utils")
        logger.debug('Checking key_share failed: %s', repr(e), exc_info=True)
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
