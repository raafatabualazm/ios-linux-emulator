#!/usr/bin/env python3
"""Inspect, wake, capture, or stop a VM launched by run.py."""
import argparse
import json
from pathlib import Path
import socket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('socket', type=Path)
    parser.add_argument('command', choices=['status', 'wake', 'screenshot', 'quit'])
    parser.add_argument('--output', type=Path, help='Absolute screenshot destination (PPM)')
    args = parser.parse_args()
    if args.command == 'screenshot' and args.output is None:
        parser.error('screenshot requires --output')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect(str(args.socket.expanduser().resolve()))
        with connection.makefile('rwb') as stream:
            json.loads(stream.readline())  # server greeting

            def request(name, arguments=None):
                message = {'execute': name}
                if arguments is not None:
                    message['arguments'] = arguments
                stream.write((json.dumps(message) + '\n').encode())
                stream.flush()
                while True:
                    reply = json.loads(stream.readline())
                    if 'error' in reply:
                        raise RuntimeError(reply['error'])
                    if 'return' in reply:
                        return reply['return']

            request('qmp_capabilities')
            commands = {
                'status': ('query-status', None),
                'wake': ('human-monitor-command', {'command-line': 'sendkey f5'}),
                'quit': ('quit', None),
                'screenshot': ('screendump', {'filename': str(args.output.expanduser().resolve())}
                               if args.output else None),
            }
            print(json.dumps(request(*commands[args.command])))


if __name__ == '__main__':
    main()
