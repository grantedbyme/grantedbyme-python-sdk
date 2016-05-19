#
# The MIT License (MIT)
#
# Copyright (c) 2016 GrantedByMe
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""
GrantedByMe Python SDK
.. moduleauthor:: GrantedByMe <info@grantedby.me>
"""
# -*- coding: utf-8 -*-

import time
import os
from enum import Enum

import requests

from .gbm_crypto import GBMCrypto


class TokenType(Enum):
    """TokenType Enumerations"""
    unknown = 0
    account = 1
    session = 2
    authorize = 3
    activate = 4
    deactivate = 5


class GrantedByMe(object):
    """GrantedByMe class"""

    VERSION = '1.0.11'
    BRANCH = 'master'
    API_URL = 'https://api.grantedby.me/v1/service/'

    def __init__(self, private_key=None, private_key_file=None, server_key=None, server_key_file=None, api_url=None):
        """Constructor"""
        self.private_key = private_key
        self.server_key = server_key
        if not private_key and private_key_file and os.path.isfile(private_key_file):
            self.private_key = open(private_key_file).read()
        if not server_key and server_key_file and os.path.isfile(server_key_file):
            self.server_key = open(server_key_file).read()
        self.api_version = 'v1'
        self.api_resource = 'service'
        if api_url:
            self.api_url = api_url
        else:
            self.api_url = GrantedByMe.API_URL

    def _activate_handshake(self):
        """Activation RSA key exchange"""
        private_key = GBMCrypto.load_private_key(self.private_key.encode('utf-8'))
        public_key = GBMCrypto.serialize_key(private_key.public_key()).decode('utf-8')
        params = {
            'public_key': public_key,
            'timestamp': int(time.time())
        }
        response = requests.post(self.api_url + 'activate_handshake/', json=params, headers=self.get_headers())
        return response.json()

    def activate_service(self, service_key):
        """Service activation"""
        # generate RSA key pair if not exists
        if not self.private_key:
            private_rsa = GBMCrypto.generate_keypair()
            self.private_key = GBMCrypto.serialize_key(private_rsa).decode('utf-8')
        # get server public key if not exists
        if not self.server_key:
            handshake = self._activate_handshake()
            if handshake and handshake['success'] and handshake['public_key']:
                self.server_key = handshake['public_key']
        # API call
        params = self.get_params()
        params['grantor'] = GBMCrypto.random_string()
        params['service_key'] = service_key
        return self.post(params, 'activate_service')

    def deactivate_service(self):
        """Service deactivation"""
        params = self.get_params()
        return self.post(params, 'deactivate_service')

    def link_account(self, token, grantor):
        """User account creation"""
        params = self.get_params()
        params['token'] = token
        params['grantor'] = grantor
        return self.post(params, 'link_account')

    def unlink_account(self, grantor):
        """User account deletion"""
        params = self.get_params()
        params['grantor'] = GBMCrypto.sha512(grantor)
        return self.post(params, 'unlink_account')

    def get_session_token(self, client_ip=None, client_ua=None):
        """Helper method for session token creation"""
        return self.get_token(TokenType.session.value, client_ip, client_ua)

    def get_account_token(self, client_ip=None, client_ua=None):
        """Helper method for account token creation"""
        return self.get_token(TokenType.account.value, client_ip, client_ua)

    def get_register_token(self, client_ip=None, client_ua=None):
        """Helper method for registration token creation"""
        return self.get_token(TokenType.activate.value, client_ip, client_ua)

    def get_token(self, type, client_ip=None, client_ua=None):
        """Retrieve a new token for type"""
        params = self.get_params()
        params['token_type'] = type
        if client_ua:
            params['http_user_agent'] = client_ua
        if client_ip:
            params['remote_addr'] = client_ip
        return self.post(params, 'get_session_token')

    def get_token_state(self, token, client_ip=None, client_ua=None):
        """Retrieve an existing token state"""
        params = self.get_params()
        params['token'] = token
        if client_ua:
            params['http_user_agent'] = client_ua
        if client_ip:
            params['remote_addr'] = client_ip
        return self.post(params, 'get_session_state')

    def post(self, params, operation):
        """Sends a HTTP POST message"""
        encrypted_params = GBMCrypto.encrypt_compound(params, self.server_key, self.private_key)
        encrypted_params['public_hash'] = GBMCrypto.sha512(self.server_key)
        page_url = self.api_url + operation + '/'
        response = requests.post(page_url, json=encrypted_params, headers=self.get_headers())
        return GBMCrypto.decrypt_compound(response.json(), self.server_key, self.private_key)

    def get_ua(self):
        """Returns the SDK user agent string"""
        return 'GrantedByMe/' + GrantedByMe.VERSION + '-' + GrantedByMe.BRANCH + ' (Python)'

    def get_headers(self):
        """Returns the default header dictionary"""
        result = {
            'user-agent': self.get_ua()
        }
        return result

    def get_params(self):
        """Returns the default POST parameter dictionary"""
        result = {
            'timestamp': int(time.time())
        }
        return result
