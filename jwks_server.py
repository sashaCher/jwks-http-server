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

    def get_key(self, key_name, alg):
        if key_name not in keys:
            keys[key_name] = {
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
        return keys[key_name]

    def export_key(self, key):
        try:
            key_json = key.export(private_key=False)
        except jwk.InvalidJWKType:
            key_json = key.export()
        key_dict = json.loads(key_json, object_pairs_hook=OrderedDict)
        key_dict['kid'] = key.thumbprint()
        return key_dict

    def base64_padding(self, value):
        return value + "=" * (-len(value) % 4)

    def decode_token(self, token):
        head_b64, payl_b64, sig = token.split(".", 3) # pylint: disable=W0612
        head = base64.urlsafe_b64decode(self.base64_padding(head_b64))
        payl = base64.urlsafe_b64decode(self.base64_padding(payl_b64))
        head_dict = json.loads(head, object_pairs_hook=OrderedDict)
        payl_dict = json.loads(payl, object_pairs_hook=OrderedDict)
        return head_dict, payl_dict

    def do_GET(self): # pylint: disable=C0103
        logging.info("GET: %s", str(self.path))
        parts = self.path.strip('/').split('/')

        if len(parts) == 2:
            key_name, alg = parts[0], parts[1]
            key = self.get_key(key_name, alg)
            resp = json.dumps({
                'keys': [
                    self.export_key(key)
                ]
            })
        else:
            key_list = []
            for key in keys.values():
                key_list.append(self.export_key(key))
            resp = json.dumps({
                'keys': key_list
            })

        self.reply(resp)

    def do_POST(self): # pylint: disable=C0103
        logging.info("POST %s", str(self.path))

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        logging.info("BODY %s", post_data.decode('utf-8'))

        key_name, alg = self.path.strip('/').split('/')
        key = self.get_key(key_name, alg)

        head, payl = self.decode_token(post_data.decode('utf-8'))
        head['alg'] = alg
        head['kid'] = key.thumbprint()

        token = jwt.JWT(header=head, claims=payl)
        token.make_signed_token(key)
        self.reply(token.serialize())

    def do_DELETE(self): # pylint: disable=C0103
        logging.info("DELETE %s", str(self.path))
        parts = self.path.strip('/').split('/')
        if len(parts) == 2:
            del keys[parts[0]]
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
parser.add_argument(
    '-p',
    '--port',
    type=int,
    default=DEFAULT_PORT,
    help="defines http server port (default: {})".format(DEFAULT_PORT))
args = parser.parse_args()
run(args.port)
