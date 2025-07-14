import asyncio
import argparse

from slynk import main

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=None, help='Server port')
    parser.add_argument('--type', type=str, default=None, help='Proxy type')
    args = parser.parse_args()

    asyncio.run(main(server_port=args.port, proxy_type=args.type))
