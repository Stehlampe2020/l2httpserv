#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import main

class HTTPFileManager(main.L2HTTPServ):
    """Web file manager based on L2HTTPServ"""
    _implemented_methods:tuple[str, ...] = property( # Make this read-only by only supplying a getter
        (lambda: 'DELETE,GET,HEAD,POST,PUT,TRACE'.split(','))
    )

    def __init__(self, *args, **kwargs):
        """Initialize the request handler"""
        super().__init__(*args, **kwargs)

    def handle(self):
        """Prehandle all requests"""
        super().prehandle()
        match self._req_type:
            # The two most common ones are checked first to reduce computation time
            case 'GET':
                self._handle_GET()
            case 'POST':
                self._handle_POST()
            # The other methods are handled in alphabetic order
            case 'DELETE':
                self._handle_unsupported_method()
            case 'HEAD':
                self._handle_HEAD()
            case 'PUT':
                self.__handle_put()
            case 'TRACE':
                self._handle_TRACE()
            # In case none of the above methods is used:
            case method:
                self._handle_unsupported_method()

    def _handle_DELETE(self):
        """Handle DELETE requests"""

    def _handle_GET(self):
        """Handle GET requests"""
        if self._req_path == '/.__L2HTTPFileManager.shutdownServer':
            self._response_http_status(200)
            self._response_set_header('Content-type', 'text/plain; charset=UTF-8')
            self._response_data['body'] = b'Stopping server...'
            self._response_send()
            self._stop_server()
        else:
            with open('examples/filemanager.baseview.html', 'r') as baseview:
                self._response_http_status(200)
                self._response_set_header('Content-type', 'text/html; charset=UTF-8')
                self._response_data['body'] = baseview.read()
                self._response_send()

    def _handle_HEAD(self):
        """Handle HEAD requests"""

    def _handle_POST(self):
        """Handle POST requests"""

    def _handle_PUT(self):
        """Handle PUT requests"""

if __name__ == '__main__':
    """Do this if the module is called as a script."""
    import argparse
    argparser:argparse.ArgumentParser = argparse.ArgumentParser(
        prog='HTTPFileManager',
        description='A simple file manager rendered in a browser, written in Python3.',
        epilog='This thing is NOT IN ANY WAY secure, so don\'t expose it to the internet if you want your files to be safe!'
    )
    argparser.add_argument('-s', '--ssl', action='store_true', help="Encrypt the connections with SSL ('certfile.crt' and 'keyfile.key' must be present in working dir)")
    main.init_server(HTTPFileManager, enable_ssl=(argparser.parse_args().ssl))