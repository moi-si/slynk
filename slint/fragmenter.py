import asyncio
import socket
import random

from .logger_with_context import logger, domain_policy

logger = logger.getChild('fragmenter')

def fragment_content(data: str, num: int) -> list:
    """
    frag <data> into num pieces
    """
    data_length = len(data)
    fragmented_content = []
    if len(data) > 1:
        dividing_points = random.sample(
            range(1, data_length), min(num, data_length - 1)
        )
    else:
        fragmented_content.append(data)
        return
    dividing_points.append(0)
    dividing_points.append(data_length)
    dividing_points.sort()
    for i in range(len(dividing_points) - 1):
        fragmented_content.append(data[dividing_points[i]:dividing_points[i + 1]])
    return fragmented_content

def fragment_pattern(data, pattern, len_sni: int, num_pieces: int):
    """
    fragment pattern into at least num parts.
    the first part of the pattern contains in
    fragmented_data[0]
    """
    fragmented_data = []
    position = data.find(pattern)
    logger.debug(f"{pattern} {position}")
    if position == -1:
        return fragment_content(data, 2 * num_pieces)

    pattern_length = len(pattern)
    data_length = len(data)

    fragmented_data.extend(fragment_content(data[0:position], num_pieces))

    l = len(fragmented_data)

    if len_sni >= len(pattern) / 2:
        len_sni = int(len(pattern) / 2)
        logger.info("len_sni too big so it has been set to %d", len_sni)

    num = int(pattern_length / len_sni)

    if num * len_sni < pattern_length:
        num += 1

    for i in range(num):
        fragmented_data.append(
            data[position + i * len_sni:position + (i + 1) * len_sni]
        )

    r = len(fragmented_data)

    fragmented_data.extend(
        fragment_content(data[position + num * len_sni:], num_pieces)
    )
    return fragmented_data, l, r

async def send_chunks(writer, data, sni):
    '''Send fragmentted data'''
    try:
        sock = writer.get_extra_info('socket')
        if sock is None:
            raise RuntimeError('Failed to get socket of writer.')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        policy = domain_policy.get()

        logger.info('To send: %d Bytes.', len(data))
        logger.debug('To send: %s', repr(data))
        base_header = data[:3]
        record = data[5:]

        splited_tls_data, l, r = fragment_pattern(
            record, sni, policy["len_tls_sni"], policy["num_tls_pieces"]
        )
        tcp_data = b''
        for i, _ in enumerate(splited_tls_data):
            tmp = splited_tls_data[i] = (
                base_header
                + int.to_bytes(len(splited_tls_data[i]), byteorder="big", length=2)
                + splited_tls_data[i]
            )
            tcp_data += tmp
            logger.debug('Added chunk: of %d bytes.', len(tmp))
            logger.debug('Added chunk: %s', tmp)

        logger.info('TLS splited: %d Bytes.', len(tcp_data))
        logger.debug('TLS splited: %s', repr(tcp_data))

        lenl = 0
        for i in range(l):
            lenl += len(splited_tls_data[i])
        lenr = lenl
        for i in range(l, r):
            lenr += len(splited_tls_data[i])

        splited_tcp_data, l, r = fragment_pattern(
            tcp_data,
            tcp_data[lenl:lenr],
            policy["len_tcp_sni"],
            policy["num_tcp_pieces"],
        )

        for packet in splited_tcp_data:
            writer.write(packet)
            await writer.drain()
            logger.debug(
                "TCP sent: %d bytes. And 'll sleep for %d seconds.",
                len(packet),
                policy["send_interval"],
            )
            logger.debug("TCP sent: %s", repr(packet))
            await asyncio.sleep(policy["send_interval"])

    except Exception as e:
        logger.error('Failed to send chunks due to %s', repr(e))
    finally:
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
