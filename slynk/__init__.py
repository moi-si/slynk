__version__ = '0.1.0'

import asyncio

from .config import CONFIG
from .logger_with_context import logger, client_port, domain_policy, remote_host
from .remote import get_connection
from . import fragmenter
from . import dns_resolver
# from . import fakedesync
from . import utils

async def upstream(reader, remote_writer, policy):
    try:
        data = await reader.read(16384)
        if data == b'':
            logger.info(
                'Client closed connection to %s immediately.', remote_host.get()
            )
            return
        if policy.get('safety_check') and (
            has_key_share := utils.check_key_share(data)
            ) != 1:
            raise RuntimeError('Not a TLS 1.3 connection', has_key_share)
        sni = utils.extract_sni(data)
        if sni is None:
            remote_writer.write(data)
            await remote_writer.drain()
        else:
            mode = policy.get('mode')
            if mode == 'TLSfrag':
                await fragmenter.send_chunks(remote_writer, data, sni)
            elif mode == 'FAKEdesync':
                await fake_desync.send_data_with_fake(
                    remote_writer, data, sni, policy
                )
            elif mode == 'DIRECT':
                remote_writer.write(data)
                await remote_writer.drain()
            elif mode == 'GFWlike':
                raise RuntimeError(f'{remote_host.get()} has been banned.')
        while True:
            data = await reader.read(16384)
            if data == b'':
                logger.info('Client closed connection to %s.', remote_host.get())
                return
            remote_writer.write(data)
            await remote_writer.drain()
    except Exception as e:
        logger.error('Upstream from %s: %s', remote_host.get(), repr(e))

async def downstream(remote_reader, writer, policy):
    try:
        data = await remote_reader.read(16384)
        if data == b'':
            logger.info(
                'Remote server %s closed connection to immediately.',
                remote_host.get()
            )
            return
        writer.write(data)
        await writer.drain()
        while True:
            data = await remote_reader.read(16384)
            if data == b'':
                logger.info(
                    'Remote server %s closed connection.', remote_host.get()
                )
                return
            writer.write(data)
            await writer.drain()
    except Exception as e:
        logger.error('Downstream from %s: %s', remote_host.get(), repr(e))

async def http_handler(reader, writer):
    remote_writer = None
    try:
        client_port.set(writer.get_extra_info('peername')[1])
        header = await reader.readuntil(b'\r\n\r\n')
        request_line = header.decode('iso-8859-1').splitlines()[0]
        logger.info(request_line)
        words = request_line.split()
        method, path = words[:2]
        if path.startswith('/'):
            writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')
            await writer.drain()
            return
        if method == 'CONNECT':
            r_host, r_port = path.split(':')
            remote_host.set(r_host)
            try:
                remote_reader, remote_writer = await get_connection(r_host, int(r_port))
            except Exception as e:
                logger.error(
                    'Failed to connect to %s:%s due to %s', r_host, r_port, repr(e)
                )
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                return
            policy = domain_policy.get()
            if policy is None:
                raise RuntimeError(f'Failed to get policy for {remote_host.get()}')
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            tasks = (
                asyncio.create_task(upstream(reader, remote_writer, policy)),
                asyncio.create_task(downstream(remote_reader, writer, policy))
            )
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        elif method in (
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'
        ) and path.startswith('http://'):
            path = path.removeprefix('http://')
            logger.info('Redirect HTTP to HTTPS for %s', path)
            message = (
                f'HTTP/1.1 301 Moved Permanently\r\nLocation: https://{path}\r\n\r\n'
            )
            writer.write(message.encode('iso-8859-1'))
            await writer.drain()
        else:
            logger.warning('Bad request: %s', request_line)
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
    except Exception as e:
        logger.error('HTTP handler exception for: %s', repr(e))
    finally:
        return remote_writer

async def socks5_handler(reader, writer):
    pass

async def handler(reader, writer):
    remote_writer = None
    proxy_type = CONFIG.get('proxy_type')
    try:
        if proxy_type == 'http':
            remote_writer = await http_handler(reader, writer)
        elif proxy_type == 'socks5':
            # remote_writer = await socks5_handler(reader, writer)
            raise NotImplementedError('SOCKS5 is not supported yet.')
        elif proxy_type is None:
            logger.error(
                'Proxy type not specified. '
                'Please set the `proxy_type` field ("http" or "socks5") in `config.json`.'
            )
        else:
            raise ValueError(f'Unknown proxy type: {proxy_type}')
    finally:
        logger.debug('Closing writers...')
        try:
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

async def main():
    global DNSResolver
    DNSResolver = dns_resolver.Resolver(
        CONFIG['DNS_URL'], f"http://127.0.0.1:{CONFIG['port']}"
    )
    await DNSResolver.create_session()

    print(f'Slynk v{__version__} - local relay')
    server = await asyncio.start_server(
        handler, '127.0.0.1', CONFIG['port']
    )
    print(f"Ready at 127.0.0.1:{CONFIG['port']}")

    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
    finally:
        await DNSResolver.close_session()
        print('\nExited.')
