# /usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
from uaserver import XMLHandler
from xml.sax import make_parser
from proxy_registrar import digest_response

usage_error = 'usage: python3 uaclient.py <fichero> <metodo> <opcion>'

register = 'REGISTER sip:username:serverport SIP/2.0\r\nExpires: opcion\r\n'

digest = 'Authorization: Digest response="digest"\r\n'

invite = 'INVITE sip:opcion SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n'
invite += 'o=username serverip\r\ns=nombresesion\r\nt=0\r\nm=audio puertortp RTP\r\n'

ack = 'ACK sip:opcion SIP/2.0\r\n'

bye = 'BYE sip:opcion SIP/2.0\r\n'

def metodo_register(socket, opcion):
    mess = register.replace('username', config['account_username'])
    mess = mess.replace('serverport', config['uaserver_puerto'])
    mess = mess.replace('opcion', opcion)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))

def metodo_register_con_digest(socket, opcion, response):
    mess = register.replace('username', config['account_username'])
    mess = mess.replace('serverport', config['uaserver_puerto'])
    mess = mess.replace('opcion', opcion)
    mess += digest.replace('digest', response)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))

def metodo_invite(socket, opcion):
    pass

def metodo_ack(socket, opcion):
    pass

def metodo_bye(socket, opcion):
    pass

def recibir_respuesta(socket):

    data = my_socket.recv(1024)

    return data.decode('utf-8')

if __name__ == '__main__':

    if len(sys.argv) != 4:
        sys.exit(usage_error)
    else:
        fichero = sys.argv[1]
        metodo = sys.argv[2]
        opcion = sys.argv[3]
        if metodo.upper() == 'REGISTER':
            try:
                int(opcion)
            except:
                sys.exit('se necesita un numero')

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(fichero))
    config = cHandler.get_tags()

    ip_proxy = config['regproxy_ip']
    port_proxy = int(config['regproxy_puerto'])

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:

        my_socket.connect((ip_proxy, port_proxy))

        if metodo.upper() == 'REGISTER':
            metodo_register(my_socket, opcion)
            respuesta = recibir_respuesta(my_socket)
            print('Recibiendo:\n' + respuesta)
            if 'SIP/2.0 401 Unauthorized' in respuesta:
                nonce = respuesta.split('\r\n')[1].split('"')[-2]
                response = digest_response(nonce, config['account_passwd'])
                metodo_register_con_digest(my_socket, opcion, response)
                respuesta = recibir_respuesta(my_socket)
                print('Recibiendo:\n' + respuesta)
        elif metodo.upper() == 'INVITE':
            metodo_invite(my_socket, opcion)
            respuesta = recibir_respuesta(my_socket)
        elif metodo.upper() == 'BYE':
            metodo_bye(my_socket, opcion)
            respuesta = recibir_respuesta(my_socket)
