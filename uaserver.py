# /usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

usage_error = 'usage: python3 uaserver.py <fichero>'

class XMLHandler(ContentHandler):

    def __init__(self):

        self.tags = {}
        self.atributos = {'account': ['username', 'passwd'],
                          'uaserver': ['ip', 'puerto'],
                          'rtpaudio': ['puerto'],
                          'regproxy': ['ip', 'puerto'],
                          'log': ['path'],
                          'audio': ['path']}

    def startElement(self, name, attrs):

        if name in self.atributos:
            for atributo in self.atributos[name]:
                self.tags[name + "_" + atributo] = attrs.get(atributo, '')

    def get_tags(self):

        return self.tags


class SIPHandler(socketserver.DatagramRequestHandler):

    def handle(self):

        info = self.read().decode('utf-8')
        print(info)

if __name__ =='__main__':

    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        fichero = sys.argv[1]

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(fichero))
    config = cHandler.get_tags()

    name = config['account_username']
    ip = config['uaserver_ip']
    port = int(config['uaserver_puerto'])

    serv = socketserver.UDPServer((ip, port), SIPHandler)
    try:
        print('El servidor de', name, 'esta ahora activo')
        serv.serve_forever()
    except KeyboardInterrupt:
        print('El servidor de', name, 'ha acabado su trabajo por hoy')
