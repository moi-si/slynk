__version__ = '0.2.0'

import asyncio
import socket
import os

from .config import CONFIG, basepath
from .logger_with_context import (
    logger, client_port, domain_policy, remote_host, force_close
)
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

def make_pac_resp():
    global PAC_RESP
    try:
        if os.path.exists('proxy.pac'):
            pac_path = 'proxy.pac'
        elif os.path.exists(path := os.path.join(basepath, 'proxy.pac')):
            pac_path = path
        else:
            raise FileNotFoundError('PAC file not found')
        with open(pac_path, 'rb') as f:
            pac_file = f.read().replace(
                b'{{port}}', str(CONFIG['port']).encode('iso-8859-1')
            )
            PAC_RESP = (
                'HTTP/1.1 200 OK\r\n'
                'Content_Type:application/x-ns-proxy-autoconfig\r\n'
                f'Content_Length: {len(pac_file)}\r\n\r\n'.encode('iso-8859-1')
                + pac_file
            )
            print('PAC is ready.')
    except Exception as e:
        print(
            f'Failed to make PAC response due to {repr(e)}.',
            'Server will start, but the PAC file will not be served.'
        )
        PAC_RESP = b'HTTP/1.1 404 Not Found\r\n\r\n'

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
        logger.error('Failed to close writers due to %s.', repr(e))

async def send_client_hello(
    reader, writer, remote_reader, remote_writer, r_host, r_port
):
    policy = domain_policy.get()
    if (data := await reader.read(16384)) == b'':
        raise ConnectionError(
            f'Client closed connection to {r_host} immediately.'
        )
    if policy.get('safety_check') and (
        has_key_share := utils.check_key_share(data)
    )[0] != 1:
        await utils.send_tls_alert(writer, has_key_share[1])
        raise ValueError('Not a TLS 1.3 connection', has_key_share)
    if (sni := utils.extract_sni(data)) is None:
        remote_writer.write(data)
        await remote_writer.drain()
    else:
        if policy.get('BySNIfirst') and r_host != (sni_str := sni.decode()):
            logger.info('Remote host has been changed to %s.', sni_str)
            connection = await get_connection(
                sni_str, r_port, resolver
            )
            if connection is None:
                logger.warning('New connection failed. Falling back.')
            else:
                remote_writer.transport.abort()
                remote_reader, remote_writer = connection
                r_host = sni_str
        remote_host.set(r_host)
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
    return remote_reader, remote_writer

async def upstream(reader, remote_writer):
    try:
        while (data := await reader.read(16384)) != b'':
            remote_writer.write(data)
            await remote_writer.drain()
        logger.info('Client closed connection to %s.', remote_host.get())

    except Exception as e:
        logger.error('Upstream from %s: %s', remote_host.get(), repr(e))

async def downstream(remote_reader, writer):
    try:
        if (data := await remote_reader.read(16384)) == b'':
            raise ConnectionError(
                'Remote server {remote_host.get()} closed connection immediately.'
            )
        writer.write(data)
        await writer.drain()

        while (data := await remote_reader.read(16384)) != b'':
            writer.write(data)
            await writer.drain()
        logger.info('Remote server %s closed connection.', remote_host.get())

    except Exception as e:
        logger.error('Downstream from %s: %s', remote_host.get(), repr(e))

async def http_handler(reader, writer):
    remote_writer = None
    client_port.set(writer.get_extra_info('peername')[1])

    try:
        header = await reader.readuntil(b'\r\n\r\n')
        request_line = header.decode('iso-8859-1').splitlines()[0]
        logger.info(request_line)
        method, path, _ = request_line.split()

        if path == '/proxy.pac':
            writer.write(PAC_RESP)
            await writer.drain()

        elif path.startswith('/'):
            writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            await writer.drain()

        elif method == 'CONNECT':
            r_host, r_port = path.split(':')
            connection = await get_connection(r_host, int(r_port), dns_query)
            if connection is None:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                return
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            remote_reader, remote_writer = connection
            remote_reader, remote_writer = await send_client_hello(
                reader, writer, remote_reader, remote_writer, r_host, r_port
            )
            tasks = (
                asyncio.create_task(upstream(reader, remote_writer)),
                asyncio.create_task(downstream(remote_reader, writer))
            )
            _, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

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

    except Exception as e:
        logger.error('HTTP Handler exception for: %s',repr(e))

    finally:
        await close_writers(writer, remote_writer)

async def socks5_handler(reader, writer):
    remote_writer = None
    client_port.set(writer.get_extra_info('peername')[1])

    try:
        ver = await reader.readexactly(1)
        if ver != b'\x05':
            raise ValueError('Not SOCKS5', ver)

        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)

        if 0x00 not in methods:
            raise ValueError(
                'No "no authentication required" method is provided'
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
        remote_reader, remote_writer = await send_client_hello(
            reader, writer, remote_reader, remote_writer, address, port
        )
        tasks = (
            asyncio.create_task(upstream(reader, remote_writer)),
            asyncio.create_task(downstream(remote_reader, writer))
        )
        _, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    except Exception as e:
        logger.error('SOCKS5 Handler exception for: %s', repr(e))

    finally:
        await close_writers(writer, remote_writer)

async def main():
    proxy_type = CONFIG.get('proxy_type')
    if proxy_type == 'http':
        make_pac_resp()
        handler = http_handler
    elif proxy_type == 'socks5':
        handler = socks5_handler
    elif proxy_type is None:
        logger.error(
            'Proxy type not specified. '
            'Please set the `proxy_type` field ("http" or "socks5")'
            'in `config.json`.'
        )
        return
    else:
        raise ValueError(f'Unknown proxy type: {proxy_type}')

    global dns_query
    if CONFIG['DNS_URL'].startswith('https://'):
        doh = True
        from . import doh_extension
        resolver = doh_extension.ProxiedDoHClient(
            CONFIG['DNS_URL'], CONFIG['proxy_type'], '127.0.0.1', CONFIG['port']
        )
        await resolver.init_session()
        dns_query = resolver.resolve
    else:
        import dns.asyncresolver, dns.nameserver
        doh = False
        address, port = CONFIG['DNS_URL'].split(':')
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers.append(
            dns.nameserver.Do53Nameserver(address, int(port))
        )
        async def dns_query(domain, qtype):
            result = await resolver.resolve(domain, qtype)
            return result[0].to_text()
    print('DNS resolver is ready.')

    print(f'Slynk v{__version__} - A lightweight local relay')
    server = await asyncio.start_server(
        handler, '127.0.0.1', CONFIG['port']
    )
    print(f"Ready at {proxy_type}://127.0.0.1:{CONFIG['port']}")

    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
    finally:
        if doh:
            await resolver.close_session()
        print('\nExited.')
