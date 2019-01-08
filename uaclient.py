# /usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
from uaserver import XMLHandler
from xml.sax import make_parser
from proxy_registrar import digest_response, log_writer

usage_error = 'usage: python3 uaclient.py <fichero> <metodo> <opcion>'

register = 'REGISTER sip:username:serverport SIP/2.0\r\nExpires: opcion\r\n'

digest = 'Authorization: Digest response="digest"\r\n'

invite = 'INVITE sip:opcion SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n'
invite += 'v=0\r\no=username serverip\r\ns=nombresesion\r\nt=0\r\n'
invite += 'm=audio puertortp RTP\r\n'

ack = 'ACK sip:opcion SIP/2.0\r\n'

bye = 'BYE sip:opcion SIP/2.0\r\n'


def metodo_register(socket, opcion, log_mess):
    mess = register.replace('username', config['account_username'])
    mess = mess.replace('serverport', config['uaserver_puerto'])
    mess = mess.replace('opcion', opcion)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))
    log_writer(log_mess + mess.replace('\r\n', ' '), config)


def register_con_digest(socket, opcion, response, log_mess):
    mess = register.replace('username', config['account_username'])
    mess = mess.replace('serverport', config['uaserver_puerto'])
    mess = mess.replace('opcion', opcion)
    mess += digest.replace('digest', response)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))
    log_writer(log_mess + mess.replace('\r\n', ' '), config)


def metodo_invite(socket, opcion, log_mess):
    mess = invite.replace('username', config['account_username'])
    mess = mess.replace('serverip', config['uaserver_ip'])
    mess = mess.replace('puertortp', config['rtpaudio_puerto'])
    mess = mess.replace('nombresesion', 'sesiondecorchon')
    mess = mess.replace('opcion', opcion)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))
    log_writer(log_mess + mess.replace('\r\n', ' '), config)


def metodo_ack(socket, opcion, log_mess):
    mess = ack.replace('opcion', opcion)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))
    log_writer(log_mess + mess.replace('\r\n', ' '), config)


def ejecutar_rtp(data):
    ip = data.split('\r\n')[8].split()[-1]
    puerto = data.split('\r\n')[11].split()[1]
    mp32rtp = './mp32rtp -i ' + ip + ' -p ' + puerto + ' < '
    mp32rtp += config['audio_path']
    print('Ejecutando:', mp32rtp)
    os.system(mp32rtp)


def metodo_bye(socket, opcion, log_mess):
    mess = bye.replace('opcion', opcion)
    print('Enviando:\n' + mess)
    socket.send(bytes(mess, 'utf-8'))
    log_writer(log_mess + mess.replace('\r\n', ' '), config)


def recibir_respuesta(socket):

    try:
        data = my_socket.recv(1024).decode('utf-8')
    except:
        data = ''

    return data


def trying_ringing_ok(data):

    trying = '100 Trying' in data
    ringing = '180 Ringing' in data
    ok = '200 OK' in data

    return trying and ringing and ok

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
                sys.exit('el puerto tiene que ser un numero')

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(fichero))
    config = cHandler.get_tags()

    ip_proxy = config['regproxy_ip']
    port_proxy = int(config['regproxy_puerto'])

    sent_mess = 'Sent to ' + ip_proxy + ':' + str(port_proxy) + ': '
    received_mess = 'Received from ' + ip_proxy + ':' + str(port_proxy) + ': '

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:

        my_socket.connect((ip_proxy, port_proxy))

        if metodo.upper() == 'REGISTER':
            metodo_register(my_socket, opcion, sent_mess)
            respuesta = recibir_respuesta(my_socket)
            if respuesta:
                log_mess = received_mess + respuesta.replace('\r\n', ' ')
                log_writer(log_mess, config)
                print('Recibiendo:\n' + respuesta)
                if 'SIP/2.0 401 Unauthorized' in respuesta:
                    nonce = respuesta.split('\r\n')[1].split('"')[-2]
                    response = digest_response(nonce, config['account_passwd'])
                    register_con_digest(my_socket, opcion, response, sent_mess)
                    respuesta = recibir_respuesta(my_socket)
                    log_mess = received_mess + respuesta.replace('\r\n', ' ')
                    log_writer(log_mess, config)
                    print('Recibiendo:\n' + respuesta)
            else:
                log_mess = 'Error: No server listening at ' + ip_proxy
                log_mess += ' port ' + str(port_proxy) + ': '
                log_writer(log_mess, config)
        elif metodo.upper() == 'INVITE':
            metodo_invite(my_socket, opcion, sent_mess)
            respuesta = recibir_respuesta(my_socket)
            if respuesta:
                log_mess = received_mess + respuesta.replace('\r\n', ' ')
                log_writer(log_mess, config)
                if trying_ringing_ok(respuesta):
                    metodo_ack(my_socket, opcion, sent_mess)
                    ejecutar_rtp(respuesta)
        elif metodo.upper() == 'BYE':
            metodo_bye(my_socket, opcion, sent_mess)
            respuesta = recibir_respuesta(my_socket)
            log_mess = received_mess + respuesta.replace('\r\n', ' ')
            log_writer(log_mess, config)
