import asyncio
import socket
import random

from .logger_with_context import logger, domain_policy

logger = logger.getChild('fragmenter')

def fragment_content(data: str, num: int) -> list:
    """
    fragment <data> into num pieces
    """
    if (data_length := len(data)) <= 1:
        return [data]
    dividing_points = random.sample(
        range(1, data_length), min(num, data_length - 1)
    )
    dividing_points.append(0)
    dividing_points.append(data_length)
    dividing_points.sort()
    fragmented_content = []
    for i in range(len(dividing_points) - 1):
        fragmented_content.append(
            data[dividing_points[i]:dividing_points[i + 1]]
        )
    return fragmented_content

def fragment_pattern(data, pattern, len_sni: int, num_pieces: int):
    """
    fragment pattern into at least num parts.
    the first part of the pattern contains in
    fragmented_data[0]
    """
    position = data.find(pattern)
    logger.debug('%s %d', pattern, position)
    if position == -1:
        return fragment_content(data, 2 * num_pieces)

    pattern_length = len(pattern)
    data_length = len(data)

    fragmented_data = fragment_content(data[:position], num_pieces)

    l = len(fragmented_data)

    if len_sni > len(pattern) // 2:
        len_sni = len(pattern) // 2
        num = 2
        logger.info("len_sni too big so it has been set to %d.", len_sni)
    else:
        num = pattern_length // len_sni
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
        if (sock := writer.get_extra_info('socket')) is None:
            raise RuntimeError('Failed to get socket of writer.')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        policy = domain_policy.get()

        logger.info('To send: %d bytes.', len(data))
        # logger.debug('To send: %s', repr(data))
        base_header = data[:3]
        record = data[5:]

        fragmented_tls_data, l, r = fragment_pattern(
            record, sni, policy["len_tls_sni"], policy["num_tls_pieces"]
        )
        tcp_data = b''
        for i, _ in enumerate(fragmented_tls_data):
            tmp = fragmented_tls_data[i] = (
                base_header
                + int.to_bytes(
                    len(fragmented_tls_data[i]), byteorder='big', length=2
                )
                + fragmented_tls_data[i]
            )
            tcp_data += tmp
            logger.debug('Added piece: %d bytes.', len(tmp))
            # logger.debug('Added piece: %s', tmp)

        logger.info('TLS fragmented: %d bytes.', len(tcp_data))
        # logger.debug('TLS fragmented: %s', repr(tcp_data))

        lenl = 0
        for i in range(l):
            lenl += len(fragmented_tls_data[i])
        lenr = lenl
        for i in range(l, r):
            lenr += len(fragmented_tls_data[i])

        splited_tcp_data, l, r = fragment_pattern(
            tcp_data,
            tcp_data[lenl:lenr],
            policy["len_tcp_sni"],
            policy["num_tcp_pieces"]
        )

        for packet in splited_tcp_data:
            writer.write(packet)
            await writer.drain()
            logger.debug(
                "TCP sent: %d bytes. And 'll sleep for %s seconds.",
                len(packet),
                policy["send_interval"]
            )
            # logger.debug("TCP sent: %s", repr(packet))
            await asyncio.sleep(policy["send_interval"])

        logger.info('All the chunks have been sent.')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

    except Exception as e:
        logger.error(
            'Failed to send chunks due to %s.', repr(e), exc_info=True
        )
