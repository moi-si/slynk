__version__ = '0.5.1'

import asyncio
import socket
import os
import struct

from .config import (
    CONFIG,
    basepath,
    init_cache,
    save_cache
)
from .logger_with_context import logger, conn_id, policy_ctx, force_close
from .remote import get_connection
from . import fragmenter
from . import fake_desync
from . import utils


def set_socket_linger_rst(writer):
    if (sock := writer.get_extra_info('socket')) is None:
        logger.warning('Could not get a valid socket from writer.')
        return
    sock.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)
    )

async def close_writers(writer, remote_writer):
    logger.debug('Closing writers...')
    try:
        if force_close.get() is True:
            if remote_writer:
                set_socket_linger_rst(remote_writer)
                remote_writer.transport.abort()
            set_socket_linger_rst(writer)
            writer.transport.abort()
        else:
            tasks = []
            if remote_writer:
                remote_writer.close()
                tasks.append(asyncio.create_task(remote_writer.wait_closed()))
            writer.close()
            tasks.append(asyncio.create_task(writer.wait_closed()))
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.debug('Closed writers successfully.')
    except Exception as e:
        logger.error(
            'Failed to close writers due to %s.', repr(e), exc_info=True
        )

async def upstream(reader, remote_writer, r_host):
    try:
        while (data := await reader.read(16384)) != b'':
            remote_writer.write(data)
            await remote_writer.drain()
        logger.info('Client closed connection to %s.', r_host)

    except Exception as e:
        logger.error('Upstream from %s: %s', r_host, repr(e))

async def downstream(remote_reader, writer, r_host):
    try:
        if (data := await remote_reader.read(16384)) == b'':
            logger.error(
                'Remote server %s closed connection without sending any data.',
                r_host
            )
            return
        writer.write(data)
        await writer.drain()

        while (data := await remote_reader.read(16384)) != b'':
            writer.write(data)
            await writer.drain()
        logger.info('Remote server %s closed connection.', r_host)

    except Exception as e:
        logger.error('Downstream from %s: %s', r_host, repr(e))

async def relay(
    reader, writer, remote_reader, remote_writer, r_host, r_port
):
    policy = policy_ctx.get()
    if (data := await reader.read(16384)) == b'':
        logger.error(
            'Client closed connection to %s without sending any data.',
            r_host
        )
        return
    if policy.get('tls13_only') and (
        has_key_share := utils.check_key_share(data)
    )[0] != 1:
        await utils.send_tls_alert(writer, has_key_share[1])
        raise ValueError('Not a TLS 1.3 connection', has_key_share)
    if (sni := utils.extract_sni(data)) is None:
        remote_writer.write(data)
        await remote_writer.drain()
    else:
        if policy.get('BySNIfirst') and r_host != (sni_str := sni.decode()):
            connection = await get_connection(sni_str, r_port, resolver)
            if connection is None:
                logger.warning('New connection failed. Falling back.')
            else:
                logger.info('Remote host has been changed to %s.', sni_str)
                remote_writer.transport.abort()
                remote_reader, remote_writer = connection
                r_host = sni_str
        mode = policy.get('mode')
        if mode == 'TLSfrag':
            await fragmenter.send_chunks(remote_writer, data, sni)
        elif mode == 'FAKEdesync':
            await fake_desync.send_data_with_fake(remote_writer, data, sni)
        elif mode == 'DIRECT':
            remote_writer.write(data)
            await remote_writer.drain()
        elif mode == 'GFWlike':
            force_close.set(True)
            raise RuntimeError(f'{r_host} has been banned.')

        tasks = (
            asyncio.create_task(upstream(reader, remote_writer, r_host)),
            asyncio.create_task(downstream(remote_reader, writer, r_host))
        )
        _, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    return remote_writer

async def http_handler(reader, writer):
    remote_writer = None
    conn_id.set(utils.generate_conn_id())

    try:
        header = await reader.readuntil(b'\r\n\r\n')
        request_line = header.decode('iso-8859-1').splitlines()[0]
        client_host, client_port, *_ = writer.get_extra_info('peername')
        logger.info('%s:%d sent %s', client_host, client_port, request_line)
        method, path, _ = request_line.split()

        if path == '/proxy.pac':
            writer.write(PAC_RESP)
            await writer.drain()

        elif path.startswith('/'):
            writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            await writer.drain()

        elif method == 'CONNECT':
            r_host, r_port = path.split(':')
            r_port = int(r_port)
            connection = await get_connection(r_host, r_port, dns_query)
            if connection is None:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                return
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            remote_reader, remote_writer = connection
            remote_writer = await relay(
                reader, writer, remote_reader, remote_writer, r_host, r_port
            )

        elif method in (
            'GET', 'POST', 'PUT', 'DELETE',
            'PATCH', 'HEAD', 'OPTIONS', 'TRACE'
        ) and path.startswith('http://'):
            path = path[7:]
            logger.info('Redirect HTTP to HTTPS for %s', path)
            message = (
                'HTTP/1.1 301 Moved Permanently\r\n'
                f'Location: https://{path}\r\n\r\n'
            )
            writer.write(message.encode('iso-8859-1'))
            await writer.drain()

        else:
            logger.warning('Bad request')
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()

    except asyncio.exceptions.IncompleteReadError as e:
        logger.info(repr(e))

    except Exception as e:
        logger.error(
            'Unexpected exception from HTTP handler: %s',
            repr(e), exc_info=True
        )


    finally:
        await close_writers(writer, remote_writer)

async def socks5_handler(reader, writer):
    remote_writer = None
    conn_id.set(utils.generate_conn_id())

    try:
        ver, = await reader.readexactly(1)
        if ver != 0x05:
            raise ValueError('Not SOCKS5', ver)

        nmethods, = await reader.readexactly(1)
        methods = await reader.readexactly(nmethods)

        if 0x00 not in methods:
            raise ValueError(
                'No "no authentication required" method was provided'
            )

        writer.write(b'\x05\x00') 
        await writer.drain()

        ver, cmd, _, atyp = await reader.readexactly(4)
        if ver != 0x05:
            raise ValueError(f'Invalid protocol version', ver)
        if cmd != 0x01:  # Only CONNECT
            raise ValueError(f'Unsupported CMD', cmd)

        if atyp == 0x01:  # IPv4
            ip_bytes = await reader.readexactly(4)
            address = socket.inet_ntop(socket.AF_INET, ip_bytes)
        elif atyp == 0x03:  # Domain name
            domain_length = (await reader.readexactly(1))[0]
            address = (await reader.readexactly(domain_length)).decode()
        elif atyp == 0x04:  # IPv6
            ip_bytes = await reader.readexactly(16)
            address = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            raise ValueError(f"Invalid address type", atyp)

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, 'big')
        logger.info('CONNECT %s:%d', address, port)

        if (
            connection := await get_connection(address, port, dns_query)
        ) is None:
            writer.write(
                b'\x05\x01\x00\x01' + b'\x00\x00\x00\x00' + b'\x00\x00'
            )
            await writer.drain()
            return
        writer.write(b'\x05\x00\x00\x01' + b'\x00\x00\x00\x00' + b'\x00\x00')
        await writer.drain()
        remote_reader, remote_writer = connection
        remote_writer = await relay(
            reader, writer, remote_reader, remote_writer, address, port
        )

    except ValueError as e:
        logger.warning(repr(e))

    except asyncio.exceptions.IncompleteReadError as e:
        logger.info(repr(e))

    except Exception as e:
        logger.error(
            'Unexpected exception from SOCKS5 handler: %s',
            repr(e), exc_info=True
        )

    finally:
        await close_writers(writer, remote_writer)

def generate_pac_resp(server_port):
    global PAC_RESP
    try:
        pac_path = CONFIG.get('pac_file') or 'proxy.pac'
        if not os.path.exists(pac_path):
            pac_path = os.path.join(basepath, 'proxy.pac')
        with open(pac_path, 'rb') as f:
            pac_file = f.read().replace(
                b'{{port}}', str(server_port).encode('iso-8859-1')
            ).replace(
                b'{{host}}', PAC_HOST.encode('iso-8859-1')
            )
            PAC_RESP = (
                'HTTP/1.1 200 OK\r\n'
                'Content-Type: application/x-ns-proxy-autoconfig\r\n'
                f'Content-Length: {len(pac_file)}\r\n\r\n'.encode('iso-8859-1')
                + pac_file
            )
            print('PAC is ready.')
    except Exception as e:
        print(
            f'Failed to generate PAC response due to {repr(e)}.',
            'The server will start, but the PAC file will not be served.'
        )
        PAC_RESP = b'HTTP/1.1 404 Not Found\r\n\r\n'

async def main(server_host=None, server_port=None, proxy_type=None):
    print(f'Slynk v{__version__} - A local relay to protect HTTPS connections')

    doh = False

    global PAC_HOST
    server_host = server_host or CONFIG.get('server_host') or '0.0.0.0'
    if server_host == '127.0.0.1':
        PAC_HOST = server_host
    else:
        PAC_HOST = CONFIG.get('pac_host') or utils.get_lan_ip()
        if not PAC_HOST:
            raise RuntimeError('Failed to get PAC host')

    server_port = server_port or CONFIG.get('server_port') or 3500
    if server_port is None:
        raise ValueError('Server port not specified')
    if server_port < 0 or server_port > 65535:
        raise ValueError(f'Port {server_port} is invalid')

    proxy_type = proxy_type or CONFIG.get('proxy_type')
    if proxy_type == 'http':
        generate_pac_resp(server_port)
        handler = http_handler
    elif proxy_type == 'socks5':
        handler = socks5_handler
    elif proxy_type is None:
        raise ValueError('Proxy type not specified')
    else:
        raise ValueError(f'Unknown proxy type: {proxy_type}')

    global dns_query
    if CONFIG['DNS_URL'].startswith('https://'):
        doh = True
        from . import doh_extension
        resolver = doh_extension.ProxiedDoHClient(
            CONFIG['DNS_URL'], proxy_type, '127.0.0.1', server_port
        )
        await resolver.init_session()
        dns_query = resolver.resolve
    else:
        import dns.asyncresolver, dns.nameserver
        address, port = CONFIG['DNS_URL'].split(':')
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers.append(
            dns.nameserver.Do53Nameserver(address, int(port))
        )
        async def dns_query(domain, qtype):
            result = await resolver.resolve(domain, qtype)
            return result[0].to_text()
    print('DNS client is ready.')

    init_cache()
    server = await asyncio.start_server(handler, server_host, server_port)
    print(f"Ready at {proxy_type}://{server_host}:{server_port}\n")

    try:
        async with server:
            await server.serve_forever()
    finally:
        if doh:
            await resolver.close_session()
        save_cache()
        print('Exited.')
