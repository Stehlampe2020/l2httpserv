#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket, traceback, sys, socketserver, ssl

# Constants:
HTTP_LINE_BREAK = '\r\n'.encode('ASCII')
NaN:float = float('nan')
Infinity:float = float('inf')
false:bool = False
true:bool = True

class L2HTTPServ(socketserver.StreamRequestHandler):
    """Basic HTTP request handler"""
    __implemented_methods:tuple[str, ...] = 'GET,POST'.split(',')

    __response_data:dict[str, bytes|dict[bytes, bytes]] = {
        'head': b'HTTP/1.1 200 OK',
        'headers': {
            b'Server': b'L2HTTPServ',
            b'Content-type': b'text/plain; charset=utf-8'
        },
        'body': b''
    }

    def __response_send(self):
        """Sends the response that has been built in self.__response_data"""
        self.wfile.write(self.__assemble_response(
            self.__response_data['head'],
            *(hname+b': '+self.__response_data['headers'][hname] for hname in self.__response_data['headers']),
            '',
            self.__response_data['body']
        ))

    def __response_set_header(self, hname:str|bytes, hcont:str|bytes):
        """Set a header's value"""
        if hname in (':',b':'):
            self.__response_data['head'] = hcont if type(hcont)==bytes else hcont.encode('ASCII')
        else:
            if type(hname)==str:
                hname = hname.encode('ASCII')
            if type(hcont)==str:
                hcont = hcont.encode('UTF-8')
            self.__response_data['headers'][hname] = hcont

    def __assemble_response(self, *lines:bytes|str):
        """Assembles the given lines with HTTP line breaks"""
        return HTTP_LINE_BREAK.join(
            (
                line                        # Give back the original line
                if type(line)==bytes        # if it's a byte string,
                else line.encode('UTF-8')   # otherwise encode it to be one.
            )
            for line in lines               # Do this for every given line.
        )+HTTP_LINE_BREAK                   # Add an HTTP line break at the end.

    def handle(self):
        """Base handler method"""
        #self.server.socket.accept()

        self.data:bytes = self.rfile.readline()+HTTP_LINE_BREAK

        try:
            self.req_type, self.req_uri, self.req_ver = self.data.replace(HTTP_LINE_BREAK, b'').decode('ascii').split(' ')
        except ValueError:
            self.wfile.write(self.__assemble_response(
                'HTTP/1.1 400 Bad Request',
                'Server: L2HTTPServ',
                'Content-type: text/plain; charset=utf-8',
                '',
                'L2HTTPServ cannot handle non-HTTP requests! (as the name implies)'
            ))
            if self.data==HTTP_LINE_BREAK:
                return print(f'Incoming empty request from {self.client_address[0]}:{self.client_address[1]}; probably an unused predicted connection.')
            else:
                return print(f'Incoming request from {self.client_address[0]}:{self.client_address[1]}: Bad header!\n    Header: {self.data}')

        print(f'Incoming {self.req_ver} request from {self.client_address[0]}:{self.client_address[1]}: {self.req_type} {self.req_uri}')

        match self.req_type:
            # The two most common ones are checked first to reduce computation time
            case 'GET':
                self.__handle_GET()
            case 'POST':
                self.__handle_POST()
            # The rest of them are checked in alphabetical order
            case 'CONNECT':
                self.__handle_CONNECT()
            case 'DELETE':
                self.__handle_DELETE()
            case 'HEAD':
                self.__handle_HEAD()
            case 'OPTIONS':
                self.__handle_OPTIONS()
            case 'PATCH':
                self.__handle_PATCH()
            case 'PUT':
                self.__handle_PUT()
            case 'TRACE':
                self.__handle_TRACE()
            # In case none of the above methods is used:
            case method:
                if method in self.__implemented_methods:
                    try:
                        self[f'__handle_{method}']()
                    except:
                        self.handle_unsupported_method()
                else:
                    self.handle_unsupported_method()

    def handle_unsupported_method(self):
        """Handle requests with an unsupported method"""
        self.wfile.write(self.__assemble_response(
            'HTTP/1.1 405 Unsupported method',
            f'Server: {type(self).__name__}',
            f'Allow: {", ".join(self.__implemented_methods)}',
            'Content-Type: text/plain; charset=utf-8',
            '',
            f'This server does not support {self.req_type} requests!'
        ))

    def __handle_GET(self):
        """Handle GET requests"""
        while not self.data.endswith(HTTP_LINE_BREAK*2):
            self.data += self.rfile.readline()+HTTP_LINE_BREAK

        if self.req_uri == '/favicon.ico':
            try:
                with open('favicon.ico', 'rb') as favicon:
                    self.wfile.write(self.__assemble_response(
                        'HTTP/1.1 200 OK',
                        f'Server: {type(self).__name__}',
                        'Content-Type: image/vnd.microsoft.icon',
                        '',
                        favicon.read()
                    ))
                    return
            except OSError:
                self.wfile.write(self.__assemble_response(
                    'HTTP/1.1 404 Not Found',
                    f'Server: {type(self).__name__}',
                    'Content-Type: text/plain; charset=utf-8',
                    '',
                    "The favicon could unfortunately not be found."
                ))
                return
        elif self.req_uri.split('?', 1)[0] == '/.__l2httpserv.stop': # Ignore GET parameters
            self.wfile.write(self.__assemble_response(
                'HTTP/1.1 200 Server Stopped',
                f'Server: {type(self).__name__}',
                'Content-Type: text/plain; charset=utf-8',
                '',
                'Stopped the server!'
            ))
            print(f'{self.client_address[0]} requested to stop the server!')
            self.server.shutdown()
            return

        self.wfile.write(self.__assemble_response(
            'HTTP/1.1 200 OK',
            f'Server: {type(self).__name__}',
            'Content-Type: text/html; charset=utf-8',
            '',
            """<!DOCTYPE html>
            <html>
                <head lang="en">
                    <link rel="icon" href="/favicon.ico">
                    <title>L2HTTPServ works!</title>
                    <meta name="description" content="L2HTTPServ test page">
                </head>
                <body style="background-color:green;color:white;">
                    <div style="position:fixed;top:0px;left:0px;bottom:0px;right:0px;background-color:rgba(0,0,0,0.5);backdrop-filter:blur(8px);">
                        <fieldset style="color:white;background-color:green;position:fixed;top:50%;left:50%;max-height:100vh;max-width:100vw;transform:translate(-50%, -50%);border:3px double white;border-radius:8px;"><legend style="color:white;background-color:blue;border:1px solid white;border-radius:5px;">L2HTTPServ</legend>
                            The example server works!<br>
                            Now it's your turn to write some code that does useful things with this base HTTP server.<br>
                            <br>
                            <form method="GET" action="/.__l2httpserv.stop">
                                <input type="hidden" name="doit" value="true">
                                <input type="submit" value="Stop the server" style="color:white;background-color:blue;border:1px solid white;border-radius:3px;">
                            </form>
                        </fieldset>
                    </div>
                </body>
            </html>""".replace("""
            """, '\n') # Remove the extra indent depth.
        ))

    def __handle_POST(self):
        """Handle POST requests"""

        self.__handle_GET() # The base server doesn't need to respond differently to POST requests than to GET requests, so literally just respond as if it was a GET request.

    def __handle_CONNECT(self):
        """Handle CONNECT requests"""
        self.handle_unsupported_method()

    def __handle_DELETE(self):
        """Handle DELETE requests"""
        self.handle_unsupported_method()

    def __handle_HEAD(self):
        """Handle HEAD requests"""
        self.handle_unsupported_method()

    def __handle_OPTIONS(self):
        """Handle OPTIONS requests"""
        self.handle_unsupported_method()

    def __handle_PATCH(self):
        """Handle PATCH requests"""
        self.handle_unsupported_method()

    def __handle_PUT(self):
        """Handle PUT requests"""
        self.handle_unsupported_method()

    def __handle_TRACE(self):
        """Handle TRACE requests"""
        self.handle_unsupported_method()

def init_server(req_handler, addr:str='localhost', port:int=8080, enable_ssl:bool=True, sslhostname:str|None='localhost', certfile:str|None='certfile.crt', keyfile:str|None='keyfile.key', certpass:str|None=None):
    with socketserver.ThreadingTCPServer((addr, port), req_handler, bind_and_activate=False) as server:
        server.allow_reuse_address = True
        server.timeout = 333
        if enable_ssl:
            context:ssl.SSLContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=certpass)
            server.socket = context.wrap_socket(sock=server.socket, server_hostname=sslhostname)
        server.server_bind()
        server.server_activate()
        server.serve_forever()

if __name__ == '__main__':
    """Do this if the module is called as a script."""
    import argparse
    argparser:argparse.ArgumentParser = argparse.ArgumentParser(
        prog='L2HTTPServ',
        description='A simple, dumb HTTP server written in Python3.',
        epilog='L2HTTPServ is NOT production ready, keep that in mind. It\'s only intended to be used as a base class for custom HTTP servers like shown in the /examples directory in the GIT project.'
    )
    argparser.add_argument('-s', '--ssl', action='store_true')
    init_server(L2HTTPServ, enable_ssl=(argparser.parse_args().ssl))