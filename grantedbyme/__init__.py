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


class ChallengeType(Enum):
    """ChallengeType Enumerations"""
    authorize = 1
    authenticate = 2
    profile = 4


class GrantedByMe(object):
    """GrantedByMe class"""

    VERSION = '1.0.18'
    BRANCH = 'master'
    API_URL = 'https://api.grantedby.me/v1/service/'
    USER_AGENT = 'GrantedByMe/' + VERSION + '-' + BRANCH + ' (Python)'

    def __init__(self, private_key=None, private_key_file=None, server_key=None, server_key_file=None, api_url=None):
        """
        Creates a new GrantedByMe SDK instance.
        :param private_key: Service RSA private key encoded in PEM format
        :param private_key_file: The path to the service RSA private key
        :param server_key: Server RSA public key encoded in PEM format
        :param server_key_file: The path to the server RSA public key
        :param api_url: The API server url
        :return:
        """
        self.private_key = private_key
        self.server_key = server_key
        if not private_key and private_key_file and os.path.isfile(private_key_file):
            self.private_key = open(private_key_file).read()
        if not server_key and server_key_file and os.path.isfile(server_key_file):
            self.server_key = open(server_key_file).read()
        if api_url:
            self.api_url = api_url
        else:
            self.api_url = GrantedByMe.API_URL

    def _activate_handshake(self):
        """
        Initiate key exchange for encrypted communication.
        :return:
        """
        private_key = GBMCrypto.load_private_key(self.private_key.encode('utf-8'))
        public_key = GBMCrypto.serialize_key(private_key.public_key()).decode('utf-8')
        params = self.get_params()
        params['public_key'] = public_key
        return self.post(params, 'activate_handshake')

    def activate_service(self, service_key):
        """
        Active pending service using service key.
        :param service_key: The activation service key
        :return:
        """
        # generate RSA key pair
        private_rsa = GBMCrypto.generate_keypair()
        self.private_key = GBMCrypto.serialize_key(private_rsa).decode('utf-8')
        # get server public key
        handshake = self._activate_handshake()
        if handshake and handshake['success'] and handshake['public_key']:
            self.server_key = handshake['public_key']
        # API call
        params = self.get_params()
        params['service_key'] = service_key
        return self.post(params, 'activate_service')

    def link_account(self, challenge, authenticator_secret):
        """
        Links a service user account with a GrantedByMe account.
        :param challenge: The challenge used to verify the user
        :param authenticator_secret: The secret used for user authentication
        :return:
        """
        params = self.get_params()
        params['challenge'] = challenge
        params['authenticator_secret'] = authenticator_secret
        return self.post(params, 'link_account')

    def get_challenge(self, challenge_type, client_ip=None, client_ua=None):
        """
        Returns a challenge with required type.
        :param challenge_type: The type of requested challenge
        :param client_ip: The client IP address
        :param client_ua: The client user-agent identifier
        :return:
        """
        params = self.get_params(client_ip, client_ua)
        params['challenge_type'] = challenge_type
        return self.post(params, 'get_challenge')

    def get_challenge_state(self, challenge, client_ip=None, client_ua=None):
        """
        Returns a challenge state.
        :param challenge: The challenge to check
        :param client_ip: The client IP address
        :param client_ua: The client user-agent identifier
        :return:
        """
        params = self.get_params(client_ip, client_ua)
        params['challenge'] = challenge
        return self.post(params, 'get_challenge_state')

    def revoke_challenge(self, challenge):
        """
        Notify the GrantedByMe server about the user has been logged out from the service.
        :param challenge: The challenge representing an active authentication session
        :return:
        """
        params = self.get_params()
        params['challenge'] = challenge
        return self.post(params, 'revoke_challenge')

    ########################################
    # Helpers
    ########################################

    def get_params(self, client_ip=None, client_ua=None):
        """
        Returns the default HTTP parameters.
        :param client_ip: The client IP address
        :param client_ua: The client user-agent identifier
        :return:
        """
        result = {
            'timestamp': int(time.time())
        }
        if client_ip:
            result['remote_addr'] = client_ip
        if client_ua:
            result['http_user_agent'] = client_ua
        return result

    def post(self, params, operation):
        """
        Sends a HTTP (POST) API request.
        :param params: The request parameter object
        :param operation: The API operation name
        :return:
        """
        if operation == 'activate_handshake':
            encrypted_params = params
        else:
            encrypted_params = GBMCrypto.encrypt_compound(params, self.server_key, self.private_key)
            encrypted_params['public_hash'] = GBMCrypto.sha512(self.server_key)
        page_url = self.api_url + operation + '/'
        response = requests.post(page_url, json=encrypted_params, headers={'user-agent': GrantedByMe.USER_AGENT})
        return GBMCrypto.decrypt_compound(response.json(), self.server_key, self.private_key)

    ########################################
    # Static
    ########################################

    @classmethod
    def generate_authenticator_secret(cls):
        """
        Generates a secure random authenticator secret.
        :return:
        """
        return GBMCrypto.random_string(128)

    @classmethod
    def hash_authenticator_secret(cls, authenticator_secret):
        """
        Generates hash digest of an authenticator secret.
        :param authenticator_secret: The authenticator secret to hash
        :return:
        """
        return GBMCrypto.sha512(authenticator_secret)
