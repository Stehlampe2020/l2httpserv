#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import main

class HTTPFileManager(main.L2HTTPServ):
    """Web file manager based on L2HTTPServ"""
    __implemented_methods = 'DELETE,GET,HEAD,POST,PUT'

    def __handle_DELETE(self):
        """Handle DELETE requests"""

    def __handle_GET(self):
        """Handle GET requests"""

    def __handle_HEAD(self):
        """Handle HEAD requests"""

    def __handle_POST(self):
        """Handle POST requests"""

    def __handle_PUT(self):
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
    init_server(L2HTTPServ, enable_ssl=(argparser.parse_args().ssl))