# /usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socketserver
from xml.sax import make_parser
from proxy_registrar import log_writer
from xml.sax.handler import ContentHandler

usage_error = 'usage: python3 uaserver.py <fichero>'

sdp_body = 'Content-Type: application/sdp\r\n\r\nv=0\r\n'
sdp_body += 'o=username serverip\r\ns=nombresesion\r\nt=0\r\nm=audio puertortp RTP\r\n'

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

    comando = []

    def handle(self):

        info = self.rfile.read().decode('utf-8')
        direccion_cliente = self.client_address[0] + ':' + str(self.client_address[1])
        log_mess = 'Received from ' + direccion_cliente + ': '
        log_mess += info.replace('\r\n', ' ')
        log_writer(log_mess, config)
        print('Recibido:\n' + info)
        metodo = info.split()[0]
        if metodo == 'INVITE':
            self.comando.append(info.split('\r\n')[4].split()[-1])
            sesion = info.split('\r\n')[5].split('=')[1]
            self.comando.append(info.split('\r\n')[7].split()[1])
            mess = 'SIP/2.0 100 Trying\r\n\r\n'
            mess += 'SIP/2.0 180 Ringing\r\n\r\n'
            mess += 'SIP/2.0 200 OK\r\n'
            sdp = sdp_body.replace('username', config['account_username'])
            sdp = sdp.replace('serverip', config['uaserver_ip'])
            sdp = sdp.replace('nombresesion', sesion)
            sdp = sdp.replace('puertortp', config['rtpaudio_puerto'])
            mensaje = mess + sdp
            self.wfile.write(bytes(mensaje, 'utf-8'))
            print('Enviado:\n' + mensaje)
            log_mess = 'Sent to ' + direccion_cliente + ': '
            log_mess += mensaje.replace('\r\n', ' ')
            log_writer(log_mess, config)
        elif metodo == 'ACK':
            comando = './mp32rtp -i ' + self.comando[0] + ' -p ' + self.comando[1] + ' < '
            comando += config['audio_path']
            print('Ejecutando:', comando)
            os.system(comando)
            self.comando = []
        elif metodo == 'BYE':
            self.wfile.write(b'SIP/2.0 200 OK\r\n')
            print('Enviado:\nSIP/2.0 200 OK')
            log_mess = 'Sent to ' + direccion_cliente + ': '
            log_mess += 'SIP/2.0 200 OK'
            log_writer(log_mess, config)
        else:
            self.wfile.write(b'SIP/2.0 405 Method Not Allowed\r\n')
            print('Enviado:\nSIP/2.0 405 Method Not Allowed')
            log_mess = 'Sent to ' + direccion_cliente + ': '
            log_mess += 'SIP/2.0 405 Method Not Allowed'
            log_writer(log_mess, config)

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
        log_writer('Starting...', config)
        print('El servidor de', name, 'esta ahora activo')
        serv.serve_forever()
    except KeyboardInterrupt:
        log_writer('Finishing.', config)
        print('El servidor de', name, 'ha acabado su trabajo por hoy')
