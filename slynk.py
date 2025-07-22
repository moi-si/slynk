import asyncio
import argparse

from slynk import main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Command-line options for slynk '
        '(override config.json settings).')
    parser.add_argument(
        '--host', type=str, metavar='host',default=None, help='Server host')
    parser.add_argument(
        '--port', type=int, metavar='port',default=None, help='Server port')
    parser.add_argument(
        '--type', type=str, metavar='protocol', default=None,
        help='Proxy type (HTTP or SOCKS5)')
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.type))
