#!/usr/bin/env python
#coding:utf-8
# Author:  Beining --<cnbeining#gmail.com>
# Purpose: A Chrome DCP handler.
# Created: 07/15/2015

#Original copyright info:
#Author:  Xiaoxia
#Contact: xiaoxia@xiaoxia.org
#Website: xiaoxia.org


import sys
import argparse

from threading import Thread, Lock
from struct import unpack
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from httplib import HTTPResponse, HTTPSConnection
from SocketServer import ThreadingMixIn
import socket, os, select
import time, sys, random
import threading

import select
import socket
import ssl

import socket
import urllib2

# Minimize Memory Usage
threading.stack_size(128*1024)


BufferSize = 8192
RemoteTimeout = 15

from hashlib import md5

global PROXY_MODE
PROXY_MODE = 'HTTPS'

#----------------------------------------------------------------------
def get_long_int():
    """None->int
    get a looooooong integer."""
    return str(random.randint(100000000, 999999999))

#----------------------------------------------------------------------
def get_google_header():
    """None->str
    As in https://github.com/cnbeining/datacompressionproxy/blob/master/background.js#L10-L18 .
    P.S: This repo is a fork of the original one on google code.
    """
    authValue = 'ac4500dd3b7579186c1b0620614fdb1f7d61f944'
    timestamp = str(int(time.time()))
    return 'ps=' + timestamp + '-' + get_long_int() + '-' + get_long_int() + '-' + get_long_int() + ', sid=' + md5((timestamp + authValue + timestamp).encode('utf-8')).hexdigest() + ', b=2403, p=61, c=win'

#----------------------------------------------------------------------
def check_if_ssl():
    """None->str
    Check whether DCP should use HTTPS.
    As in https://support.google.com/chrome/answer/3517349?hl=en"""
    response = urllib2.urlopen('http://check.googlezip.net/connect')
    if response.getcode() is 200 and 'OK' in response.read():
        print('INFO: Running in HTTPS mode.')
        return 'HTTPS'
    else:
        print('WARNING: Running in HTTP mode, your network admin can see your traffic!')
        return 'HTTP'

class Handler(BaseHTTPRequestHandler):
    remote = None

    # Ignore Connection Failure
    def handle(self):
        try:
            BaseHTTPRequestHandler.handle(self)
        except socket.error: pass
    def finish(self):
        try:
            BaseHTTPRequestHandler.finish(self)
        except socket.error: pass

    def sogouProxy(self):
        if self.headers["Host"].startswith('chrome_dcp_proxy_pac.cnbeining'):  #Give a PAC file
            self.wfile.write("HTTP/1.1 200 OK".encode('ascii') + b'\r\n')
            hstr = '''Host: 127.0.0.1

function FindProxyForURL(url, host) {
  if (url.substring(0,5) == 'http:' && 
      !isPlainHostName(host) && 
      !shExpMatch(host, '*.local') && 
      !isInNet(dnsResolve(host), '10.0.0.0', '255.0.0.0') && 
      !isInNet(dnsResolve(host), '172.16.0.0',  '255.240.0.0') && 
      !isInNet(dnsResolve(host), '192.168.0.0',  '255.255.0.0') && 
      !isInNet(dnsResolve(host), '127.0.0.0', '255.255.255.0') ) 
    return 'PROXY ''' + server_ip + ':' + str(server_port) + '''; DIRECT';
  return 'DIRECT';
}'''
            self.wfile.write(hstr + b'\r\n')
            return
            
        if self.remote is None or self.lastHost != self.headers["Host"]:
            if PROXY_MODE == 'HTTPS':
                context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                context.load_default_certs()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(RemoteTimeout)
                self.remote = context.wrap_socket(s, server_hostname='proxy.googlezip.net')
                self.remote.connect(('proxy.googlezip.net', 443))
            else:  #HTTP
                self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.remote.settimeout(RemoteTimeout)
                self.remote.connect(("compress.googlezip.net", 80))
        self.remote.sendall(self.requestline.encode('ascii') + b"\r\n")
        # Add Verification Tags
        self.headers["Chrome-Proxy"] = get_google_header()
        headerstr = str(self.headers).replace("\r\n", "\n").replace("\n", "\r\n")
        self.remote.sendall(headerstr.encode('ascii') + b"\r\n")
        # Send Post data
        if self.command == 'POST':
            self.remote.sendall(self.rfile.read(int(self.headers['Content-Length'])))
        response = HTTPResponse(self.remote, method=self.command)
        response.begin()

        # Reply to the browser
        status = "HTTP/1.1 " + str(response.status) + " " + response.reason
        self.wfile.write(status.encode('ascii') + b'\r\n')
        hlist = []
        for line in response.msg.headers: # Fixed multiple values of a same name
            if 'TRANSFER-ENCODING' not in line.upper():
                hlist.append(line)
        self.wfile.write("".join(hlist) + b'\r\n')

        if self.command == "CONNECT":  # NO HTTPS, as Chrome DCP does not allow HTTPS traffic
            return
        else:
            while True:
                response_data = response.read(BufferSize)
                if not response_data: break
                self.wfile.write(response_data)

    do_POST = do_GET = do_CONNECT = sogouProxy

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6


if __name__=='__main__':
    global server_ip, server_port
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', default=8080)
    parser.add_argument('-m', '--mode', default= 'HTTPS')
    parser.add_argument('-i', '--ip', default= '')
    args = vars(parser.parse_args())
    PROXY_MODE = args['mode'].upper() if str(args['mode']).upper() == 'HTTP' or str(args['mode']).upper() == 'HTTPS' else check_if_ssl()
    server_ip, server_port = str(args['ip']), int(args['port'])
    server_address = (server_ip, server_port)
    server = ThreadingHTTPServer(server_address, Handler)
    if not server_ip:
        server_ip = '127.0.0.1'
    proxy_host = "proxy.googlezip.net:443" if PROXY_MODE == 'HTTPS' else "compress.googlezip.net:80"
    print('Proxy over %s.\nPlease set your browser\'s proxy to %s.' % (proxy_host, server_address))
    print('Or use PAC file: http://chrome_dcp_proxy_pac.cnbeining.com/1.pac')
    try:
        server.serve_forever()
    except:
        os._exit(1)