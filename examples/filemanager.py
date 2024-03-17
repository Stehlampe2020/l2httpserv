#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import main

class HTTPFileManager(main.L2HTTPServ):
    """Web file manager based on L2HTTPServ"""
    __implemented_methods = 'DELETE,GET,HEAD,POST,PUT'

    def __set_header(self, hname:str, hcont:str=''):
        """Sets a header"""
