#!/usr/bin/python
import argparse
import base64
import socket
import struct
import sys
import time
import urllib2

ADD_RECORD = """{"ts": %(ts)s}
{"tag": "new"}
{"tag": "add", "objects": 1}
{"ip_addr": %(ip_addr)s, "ttl": %(ttl)s, "tl": %(tl)s, "desc": "Demo record"}
{"tag": "md5", "checksum": ""}
"""

REMOVE_RECORD = """{"ts": %(ts)s}
{"tag": "new"}
{"tag": "del", "objects": 1}
{"ip_addr": %(ip_addr)s}
{"tag": "md5", "checksum": ""}
"""

UPDATE_RECORD = """{"ts": %(ts)s}
{"tag": "new"}
{"tag": "add", "objects": 1}
{"ip_addr": %(ip_addr)s, "ttl": %(ttl)s, "tl": %(tl)s, "desc": "Demo record"}
{"tag": "del", "objects": 1}
{"ip_addr": %(ip_addr)s}
{"tag": "md5", "checksum": ""}
"""

RECORD_TO_TEXT = {'add': ADD_RECORD, 'remove': REMOVE_RECORD, 'update': UPDATE_RECORD}
DEFAULT_SERVER = 'localhost'
URL_PATTERN = 'https://%s/api/jwas/submit/ip_addr/%s'


def ipv42uint(ipv4_str):
    """Converts IPv4(1.2.3.4) format to unsigned integer."""
    return struct.unpack('!L', socket.inet_aton(ipv4_str))[0]


def http_post(server, data, auth_token, group_name):
    url = URL_PATTERN % (server, group_name)
    auth = base64.b64encode('1234:%s' % (auth_token,))
    headers = {'Content-Type': 'text/json', 'Authorization': 'Basic %s' % auth}
    req = urllib2.Request(url, data, headers)
    f = urllib2.urlopen(req)
    return f.read()


def main():
    parser = argparse.ArgumentParser(description='Submit demo JWAS data.')
    parser.add_argument('--server', type=str, default=DEFAULT_SERVER, help='Connector submission URL.')
    parser.add_argument('auth_token', metavar='auth_token', type=str, help='Auth token from SD.')
    parser.add_argument('group_name', metavar='group_name', type=str, help='JWAS group (feed) name from SD.')

    subparsers = parser.add_subparsers(dest='action', help='Command to execute.')
    add_parser = subparsers.add_parser('add', help='Add an IP to JWAS feed.')
    remove_parser = subparsers.add_parser('remove', help='Remove an IP from JWAS feed.')
    update_parser = subparsers.add_parser('update', help='Update an IP in JWAS feed.')

    add_parser.add_argument('ip_addr', metavar='ip_addr', type=str, help='IP address to add.')
    add_parser.add_argument('ttl', metavar='ttl', type=int, help='Time to live in seconds.')
    add_parser.add_argument('tl', metavar='threat_level', type=int, help='Threat level of the IP.')

    remove_parser.add_argument('ip_addr', metavar='ip_addr', type=str, help='IP address to remove.')

    update_parser.add_argument('ip_addr', metavar='ip_addr', type=str, help='IP address to change.')
    update_parser.add_argument('ttl', metavar='ttl', type=int, help='Time to live in seconds.')
    update_parser.add_argument('tl', metavar='threat_level', type=int, help='Threat level of the IP.')    

    args = vars(parser.parse_args())
    args['ts'] = int(time.time())
    args['ip_addr'] = ipv42uint(args['ip_addr'])
    text = RECORD_TO_TEXT[args['action']] % args

    http_post(args['server'], text, args['auth_token'], args['group_name'])
    print 'A Success is You!'


if __name__ == '__main__':
    sys.exit(main())
