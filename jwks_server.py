#!/usr/bin/env python3

import argparse
import base64
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import OrderedDict
from jwcrypto import jwt, jwk

DEFAULT_PORT = 8080

keys = {}


class JWKSRequestHandler(BaseHTTPRequestHandler):

    def reply(self, response):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def getKey(self, keyName, alg):
        if keyName not in keys:
            keys[keyName] = {
                'RS256': jwk.JWK.generate(kty='RSA', size=1024),
                'RS384': jwk.JWK.generate(kty='RSA', size=2048),
                'RS512': jwk.JWK.generate(kty='RSA', size=4048),
                'ES256': jwk.JWK.generate(kty='EC', crv='P-256'),
                'ES384': jwk.JWK.generate(kty='EC', crv='P-384'),
                'ES512': jwk.JWK.generate(kty='EC', crv='P-521'),
                'HS256': jwk.JWK.generate(kty='oct', size=256),
                'HS384': jwk.JWK.generate(kty='oct', size=384),
                'HS512': jwk.JWK.generate(kty='oct', size=512)
            }.get(alg, None)
        return keys[keyName]

    def exportKey(self, key):
        try:
            keyJson = key.export(private_key=False)
        except jwk.InvalidJWKType:
            keyJson = key.export()
        keyDict = json.loads(keyJson, object_pairs_hook=OrderedDict)
        keyDict['kid'] = key.thumbprint()
        return keyDict

    def base64Padding(self, value):
        return value + "=" * (-len(value) % 4)

    def decodeToken(self, token):
        headB64, paylB64, sig = token.split(".", 3)
        head = base64.urlsafe_b64decode(self.base64Padding(headB64))
        payl = base64.urlsafe_b64decode(self.base64Padding(paylB64))
        headDict = json.loads(head, object_pairs_hook=OrderedDict)
        paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
        return headDict, paylDict

    def do_GET(self):
        logging.info("GET: %s", str(self.path))
        parts = self.path.strip('/').split('/')

        if len(parts) == 2:
            key_name, alg = parts[0], parts[1]
            key = self.getKey(key_name, alg)
            resp = json.dumps({
                'keys': [
                    self.exportKey(key)
                ]
            })
        else:
            keyList = []
            for key in keys.values():
                keyList.append(self.exportKey(key))
            resp = json.dumps({
                'keys': keyList
            })

        self.reply(resp)

    def do_POST(self):
        logging.info("POST %s", str(self.path))

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        logging.info("BODY %s", post_data.decode('utf-8'))

        key_name, alg = self.path.strip('/').split('/')
        key = self.getKey(key_name, alg)

        head, payl = self.decodeToken(post_data.decode('utf-8'))
        head['alg'] = alg
        head['kid'] = key.thumbprint()

        token = jwt.JWT(header=head, claims=payl)
        token.make_signed_token(key)
        self.reply(token.serialize())

    def do_DELETE(self):
        logging.info("DELETE %s", str(self.path))
        parts = self.path.strip('/').split('/')
        if len(parts) == 2:
            key_name, alg = parts[0], parts[1]
            del keys[key_name]
        else:
            keys.clear()
        self.reply("DELETED")


def run(port, server_class=HTTPServer, handler_class=JWKSRequestHandler):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting JWKS server...')
    logging.info('Port: %d', port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping server...')

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser(description='Lightweight JWKS server')
parser.add_argument('-p', '--port', type=int, help="defines http server port (default: {})".format(DEFAULT_PORT), default=DEFAULT_PORT)
args = parser.parse_args()
run(args.port)
