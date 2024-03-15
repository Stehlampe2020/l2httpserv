#!/usr/bin/env python3
# -*- coding: utf-8 -*-

HTTP_LINE_BREAK = '\r\n'.encode('ASCII')
NaN:float = float('nan')
Infinity:float = float('inf')
false:bool = False
true:bool = True
import sys, socketserver, ssl
class L2HTTPServ(socketserver.StreamRequestHandler):
    def assemble_response(self, *lines:bytes|str):
        """Assembles the given lines with HTTP line breaks"""
        return HTTP_LINE_BREAK.join(
            (
                line                        # Give back the original line
                if type(line)==bytes        # if it's a byte string,
                else line.encode('UTF-8')   # otherwise encode it to be one.
            )
            for line in lines               # Do this for every given line.
        )+HTTP_LINE_BREAK
    def handle(self):
        """Base handler method"""
        self.data:bytes = self.rfile.readline()+HTTP_LINE_BREAK

        if self.data.startswith(b'GET /kill'):
            print(f'{self.client_address[0]} requested to kill the server!')
            self.wfile.write(self.assemble_response(
                'HTTP/1.1 500 Server killed!',
                '',
                'The server will be killed shortly!'
            ))
            import os, time
            time.sleep(1)
            os.system('fuser -k 8080/tcp; fuser -k 8080/udp')
        elif self.data.startswith(b'GET /favicon.ico'):
            with open('favicon.ico', 'rb') as favicon:
                self.wfile.write(self.assemble_response(
                    'HTTP/1.1 200 OK',
                    'Server: L2HTTPServ',
                    'Content-Type: image/vnd.microsoft.icon',
                    '',
                    favicon.read()
                ))
        elif self.data.startswith(b'GET'):
            self.handle_GET()
        elif self.data.startswith(b'POST'):
            self.handle_POST()
        else:
            # Respond:
            self.wfile.write(self.assemble_response(
                'HTTP/1.1 405 Unsupported method!',
                'Server: L2HTTPServ',
                'Allow: GET, POST',
                'Content-Type: text/plain; charset=utf-8',
                '',
                'This server currently only supports GET or POST requests!'
            ))

    def handle_GET(self):
        """Handle GET requests"""
        while not self.data.endswith(HTTP_LINE_BREAK*2):
            self.data += self.rfile.readline()+HTTP_LINE_BREAK

        #TODO: Implement meaningful responses!

        self.wfile.write(self.assemble_response(
            'HTTP/1.1 404 Not Found',
            'Server: L2HTTPServ',
            'Content-Type: text/plain; charset=utf-8',
            '',
            "Oops, looks like L2HTTPServ isn't ready yet!"
        ))
    def handle_POST(self):
        """Handle POST requests"""

        #TODO: Implement meaningful responses!

        self.wfile.write(self.assemble_response(
            'HTTP/1.1 404 Not Found',
            'Server: L2HTTPServ',
            'Content-Type: text/plain; charset=utf-8',
            '',
            "Oops, looks like L2HTTPServ isn't ready yet!"
        ))

if __name__ == '__main__':
    """Do this if the module is called as a script."""
    with socketserver.ThreadingTCPServer(('localhost', 8080), L2HTTPServ, bind_and_activate=False) as server:
        if 'ssl' in sys.argv:
            #server.socket = ssl.wrap_socket(server.socket, keyfile='./keyfile.key', certfile='./certfile.cert', server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2, ca_certs=None, do_handshake_on_connect=True, suppress_ragged_eofs=True, ciphers='ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK')
            ssl.SSLContext(protocol=ssl.PROTOCOL_SSLv23).wrap_socket(server.socket, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
        server.timeout = 333
        server.serve_forever()