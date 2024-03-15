#!/usr/bin/env bash
# -*- coding: utf-8 -*-
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout keyfile.key -out certfile.crt