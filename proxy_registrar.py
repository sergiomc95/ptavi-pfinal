# /usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import socket
import socketserver
from hashlib import sha256
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

usage_error = 'usage: python3 proxy_registrar.py <fichero>'

ok = 'SIP/2.0 200 OK\r\n'

bad_request = 'SIP/2.0 400 Bad Request\r\n'

unauthorized = 'SIP/2.0 401 Unauthorized\r\nWWW Authenticate: Digest nonce="digestnonce"\r\n'

user_not_found = 'SIP/2.0 404 User Not Found\r\n'

method_not_allowed = 'SIP/2.0 405 Method Not Allowed\r\n'

def log_writer(mess, config):
    with open(config['log_path'], 'a') as log_file:
        now = time.gmtime(time.time() + 3600)
        date_now = time.strftime('%Y%m%d%H%M%S', now)
        log_file.write(date_now + ' ' + mess.replace('\r\n', ' ') + '\n')

def digest_nonce(server_name, server_ip, server_port):

    digest = sha256()
    digest.update(bytes(server_name + server_ip + server_port, 'utf-8'))

    return digest.hexdigest()

def digest_response(nonce, passwd):

    digest = sha256()
    digest.update(bytes(nonce + passwd, 'utf-8'))

    return digest.hexdigest()

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
    sesions = {}

    def handle(self):

        self.json2register()
        self.expires_users()

        info = self.rfile.read().decode('utf-8')
        log_mess = 'Received from ' + self.client_address[0] + ':' 
        log_mess += str(self.client_address[1]) +': '
        log_mess += info.replace('\r\n', ' ')
        log_writer(log_mess, config)
        metodo = info.split()[0]
        print('Recibido:', metodo)

        if metodo == 'REGISTER':
            # saca usuario y comprueba si esta registrado,
            # si esta registrado, comprueba si el campo
            # expires es 0, si es 0 se borra al usuario
            # y se envia un 200 OK, si es distinto de 0
            # se actualiza la fecha de expiracion
            # si el usuario no esta registrado, se envia
            # un 401 Unauthorized
            user = info.split()[1].split(':')[1]
            if user in self.users:
                exp = int(info.split('\r\n')[1].split()[-1])
                if exp != 0:
                    now = time.gmtime(time.time() + 3600 + exp)
                    expires_date = time.strftime('%Y-%m-%d %H:%M:%S', now)
                    self.users[user]['expires'] = expires_date
                else:
                    del self.users[user]
                self.wfile.write(bytes(ok, 'utf-8'))
                log_mess = 'Sent to ' + self.client_address[0] + ':' 
                log_mess += str(self.client_address[1]) +': '
                log_mess += ok.replace('\r\n', ' ')
                log_writer(log_mess, config)
                print('Respondido: 200 OK')
            else:
                name = config['server_name']
                ip = config['server_ip']
                port = config['server_puerto']
                nonce = digest_nonce(name, ip, port)
                if 'Digest response' in info:
                    user_response = info.split('\r\n')[2].split('"')[-2]
                    passwd = self.passwd[user]
                    response = digest_response(nonce, passwd)
                    if user_response == response:
                        exp = int(info.split('\r\n')[1].split()[-1])
                        user_port = info.split('\r\n')[0].split(':')[-1].split()[0]
                        user_ip = self.client_address[0]
                        expires_time = time.gmtime(time.time() + 3600 + exp)
                        expires_date = time.strftime('%Y-%m-%d %H:%M:%S', expires_time)
                        self.users[user] = {'ip': user_ip,
                                            'puerto': user_port,
                                            'expires': expires_date}
                        self.wfile.write(bytes(ok, 'utf-8'))
                        log_mess = 'Sent to ' + self.client_address[0] + ':' 
                        log_mess += str(self.client_address[1]) +': '
                        log_mess += ok.replace('\r\n', ' ')
                        log_writer(log_mess, config)
                        print('Respondido: 200 OK')
                    else:
                        self.wfile.write(bytes(bad_request, 'utf-8'))
                        log_mess = 'Sent to ' +self.client_address[0] + ':' 
                        log_mess += str(self.client_address[1]) +': '
                        log_mess += bad_request.replace('\r\n', ' ')
                        log_writer(log_mess, config)
                        print('Respondido: 400 Bad Request')
                else:
                    mess = unauthorized.replace('digestnonce', nonce)
                    self.wfile.write(bytes(mess, 'utf-8'))
                    log_mess = 'Sent to ' + self.client_address[0] + ':' 
                    log_mess += str(self.client_address[1]) +': '
                    log_mess += mess.replace('\r\n', ' ')
                    log_writer(log_mess, config)
                    print('Respondido: 401 Unauthorized')
        elif metodo == 'INVITE':
            # saca el usuario que envia el mensaje, y comprueba
            # si esta registrado, si lo esta saca usuario destino 
            # y mira si esta registrado, si ambos estan registrados,
            # reenvia el mensaje, si el usuario destino no esta
            # registrado, envia un 404 User Not Found, y si el
            # usuario que envia el mensaje no esta registrado,
            # envia un 401 Unauthrized
            user_src = info.split('\r\n')[4].split()[0].split('=')[1]
            user_dst = info.split('\r\n')[0].split()[1].split(':')[1]
            sesion_name = info.split('\r\n')[5].split('=')[1]
            if user_src in self.users and user_dst in self.users:
                respuesta = self.reenviar(user_dst, info)
                if respuesta != '':
                    self.sesions[sesion_name] = [user_src, user_dst]
                self.wfile.write(bytes(respuesta, 'utf-8'))
                log_mess = 'Sent to ' + self.client_address[0] + ':' 
                log_mess += str(self.client_address[1]) +': '
                log_mess += respuesta.replace('\r\n', ' ')
                log_writer(log_mess, config)
            else:
                self.wfile.write(bytes(user_not_found, 'utf-8'))
                log_mess = 'Sent to ' + self.client_address[0] + ':' 
                log_mess += str(self.client_address[1]) +': '
                log_mess += user_not_found.replace('\r\n', ' ')
                log_writer(log_mess, config)
        elif metodo == 'ACK':
            # igual que el invite
            user_dst = info.split()[1].split(':')[1]
            if user_dst in self.users:
                respuesta = self.reenviar(user_dst, info)
                self.wfile.write(bytes(respuesta, 'utf-8'))
                log_mess = 'Sent to ' + self.client_address[0] + ':' 
                log_mess += str(self.client_address[1]) +': '
                log_mess += respuesta.replace('\r\n', ' ')
                log_writer(log_mess, config)
            else:
                self.wfile.write(bytes(user_not_found, 'utf-8'))
                log_mess = 'Sent to ' + self.client_address[0] + ':' 
                log_mess += str(self.client_address[1]) +': '
                log_mess += user_not_found.replace('\r\n', ' ')
                log_writer(log_mess, config)
        elif metodo == 'BYE':
            # igual que el invite, pero ademas comprueba que los 
            # usuarios estan en la sesion
            user_dst = info.split()[1].split(':')[1]
            if user_dst in self.users:
                self.delete_sesion(user_dst)
                respuesta = self.reenviar(user_dst, info)
                self.wfile.write(bytes(respuesta, 'utf-8'))
                log_mess = 'Sent to ' + self.client_address[0] + ':' 
                log_mess += str(self.client_address[1]) +': '
                log_mess += respuesta.replace('\r\n', ' ')
                log_writer(log_mess, config)
            else:
                self.wfile.write(bytes(user_not_found, 'utf-8'))
        else:
            # envia 405 Method Not Allowed
            self.wfile.write(bytes(method_not_allowed, 'utf-8'))
            log_mess = 'Sent to ' + self.client_address[0] + ':' 
            log_mess += str(self.client_address[1]) +': '
            log_mess += method_not_allowed.replace('\r\n', ' ')
            log_writer(log_mess, config)
            print('Respondido: 405 Method Not Allowed')

        self.register2json()

    def delete_sesion(self, user_dst):
        sesions = []
        for sesion in self.sesions:
            if user_dst in self.sesions[sesion]:
                sesions.append(sesion)
        for sesion in sesions:
            self.sesions.pop(sesion)

    def register2json(self):
        with open(config['database_path'], "w") as jsonfile:
            json.dump(self.users, jsonfile, indent=3)

    def json2register(self):
        try:
            with open(config['database_path'], "r") as jsonfile:
                self.users = json.load(jsonfile)
            with open(config['database_passwdpath'], "r") as jsonfile:
                self.passwd = json.load(jsonfile)
        except FileNotFoundError:
            pass

    def expires_users(self):
        now = time.gmtime(time.time() + 3600)
        date_now = time.strftime('%Y-%m-%d %H:%M:%S', now)
        deleted = []
        for user in self.users:
            if date_now > self.users[user]['expires']:
                deleted.append(user)
        for user in deleted:
            del self.users[user]

    def reenviar(self, user_dst, mensaje):
        ip_dst = self.users[user_dst]['ip']
        puerto_dst = int(self.users[user_dst]['puerto'])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.connect((ip_dst, puerto_dst))
            log_mess = 'Sent to ' + ip_dst + ':' + str(puerto_dst) +' :'
            log_mess += mensaje.replace('\r\n', ' ')
            log_writer(log_mess, config)
            my_socket.send(bytes(mensaje, 'utf-8'))
            try:
                data = my_socket.recv(1024).decode('utf-8')
                log_mess = 'Received from ' + ip_dst + ':' + str(puerto_dst) +' :'
                log_mess += mensaje.replace('\r\n', ' ')
                log_writer(log_mess, config)
            except ConnexionRefusedError:
                data = ''
                log_mess = 'Error: No server listening at' + ip_dst + ' port ' + str(puerto_dst)
                log_writer(log_mess, config)
        return data

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
        log_writer('Starting...', config)
        print(name, 'esta ahora activo')
        serv.serve_forever()
    except KeyboardInterrupt:
        log_writer('Finishing.', config)
        print(name, 'ha acabado su trabajo por hoy')
