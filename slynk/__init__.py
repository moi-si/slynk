__version__ = '0.0.1'

import asyncio

from .config import CONFIG
from .logger_with_context import logger, client_port, domain_policy, remote_host
from .remote import get_connection
from . import fragmenter
from . import dns_resolver
# from . import ttlfaker
from . import utils

async def upstream(reader, remote_writer, policy):
    try:
        data = await reader.read(16384)
        if data == b'':
            raise ConnectionError('Client closed connection at first.')
        sni = utils.extract_sni(data)
        if sni is None:
            remote_writer.write(data)
            await remote_writer.drain()
        else:
            mode = policy.get('mode')
            if mode == 'TLSfrag':
                await fragmenter.send_chunks(remote_writer, data, sni)
            elif mode == 'FAKEdesync':
                # await ttlfaker.send_after_faking(remote_writer, data)
                raise NotImplementedError("FAKEdesync is not supported yet.")
            elif mode == 'DIRECT':
                remote_writer.write(data)
                await remote_writer.drain()
            elif mode == 'GFWlike':
                raise ConnectionError(f'{remote_host.get()} has been banned.')
        while True:
            data = await reader.read(16384)
            if data == b'':
                raise ConnectionError('Client closed connection.')
            remote_writer.write(data)
            await remote_writer.drain()
    except Exception as e:
        logger.info('Upstream from %s: %s', remote_host.get(), repr(e))

async def downstream(remote_reader, writer, policy):
    try:
        data = await remote_reader.read(16384)
        if data == b'':
            raise ConnectionError('Remote host closed connection at first.')
        if policy.get('safety_check') and utils.detect_tls_version_by_keyshare(data) == -1:
            raise RuntimeError('Not a TLS 1.3 connection')
        writer.write(data)
        await writer.drain()
        while True:
            data = await remote_reader.read(16384)
            if data == b'':
                raise ConnectionError('Remote host closed connection.')
            writer.write(data)
            await writer.drain()
    except Exception as e:
        logger.info('Downstream from %s: %s', remote_host.get(), repr(e))

async def handler(reader, writer):
    remote_writer = None
    try:
        client_port.set(writer.get_extra_info('peername')[1])
        header = await reader.readuntil(b'\r\n\r\n')
        request_line = header.decode('iso-8859-1').splitlines()[0]
        logger.info(request_line)
        words = request_line.split()
        method, path = words[:2]
        if method == 'CONNECT':
            r_host, r_port = path.split(':')
            remote_host.set(r_host)
            try:
                remote_reader, remote_writer = await get_connection(r_host, int(r_port))
            except Exception:
                logger.error(f'Failed to connect to {r_host}:{r_port}.')
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                raise
            policy = domain_policy.get()
            if policy is None:
                raise RuntimeError(f'Failed to get policy for {remote_host.get()}.')
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            tasks = {
                asyncio.create_task(upstream(reader, remote_writer, policy)),
                asyncio.create_task(downstream(remote_reader, writer, policy))
            }
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending)
        elif method in (
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'
        ):
            path = path.removeprefix('http://')
            logger.info('Redirect HTTP to HTTPS for %s', path)
            message = (
                f'HTTP/1.1 301 Moved Permanently\r\nLocation: https://{path}\r\n\r\n'
            )
            writer.write(message.encode('iso-8859-1'))
            await writer.drain()
        else:
            logger.warning('Unknown HTTP method: %s', method)
    except Exception as e:
        logger.error('Handler exception for: %s', repr(e))
    finally:
        tasks_to_close = {asyncio.create_task(writer.wait_closed())}
        if remote_writer:
            remote_writer.close()
            tasks_to_close.add(asyncio.create_task(remote_writer.wait_closed()))
        writer.close()
        await asyncio.gather(*tasks_to_close, return_exceptions=True)

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
