# /usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

usage_error = 'usage: python3 proxy_registrar.py <fichero>'

def digest_nonce(server_name, server_ip, server_port):
    pass

def digest_response(nonce, passwd):
    pass

class XMLHandler(ContentHandler):

    def __init__(self):
        self.tags = {}
        self.atributos = {'server': ['name', 'ip', 'puerto'],
                          'database': ['path', 'passwdpath'],
                          'log': ['path']}

    def startElement(self, name, attrs):
        if name in self.atributos:
            for atributo in self.atributos[name]:
                self.tags[name + "_" + atributo] = attrs.get(atributo, '')

    def get_tags(self):
        return self.tags


class SIPRegisterHandler(socketserver.DatagramRequestHandler):

    users = {}
    passwd = {}

    def handle(self):
        info = self.rfile.read().decode('utf-8')
        print(info)

    def register2json(self):
        with open(config['database_path'], "w") as jsonfile:
            json.dump(self.users, jsonfile, indent=3)

    def json2register(self):
        try:
            with open(config['database_path'], "r") as jsonfile:
                self.users = json.load(jsonfile)
            with open(config['database_passwdpath'], "r") as jsonfile:
                self.passwd = json.load(jsonfile)
        except:
            pass

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

    name = config['server_name']
    ip = config['server_ip']
    port = int(config['server_puerto'])

    serv = socketserver.UDPServer((ip, port), SIPRegisterHandler)
    try:
        print(name, 'esta ahora activo')
        serv.serve_forever()
    except KeyboardInterrupt:
        print(name, 'ha acabado su trabajo por hoy')
