import string
import random
import traceback
import os
from copy import deepcopy
from typing import Union
import requests
from bson.json_util import loads


''' PENQUINS - Processing ENormous Queries of ztf Users INStantaneously '''
__version__ = '0.1.0'


Num = Union[int, float]
QueryPart = Union['task', 'result']


class Kowalski(object):
    """
        Query ZTF TDA databases
    """

    # def __init__(self, protocol='http', host='127.0.0.1', port=8000, verbose=False,
    #              username=None, password=None):

    def __init__(self, protocol='https', host='kowalski.caltech.edu', port=443, verbose=False,
                 username=None, password=None):

        assert username is not None, 'username must be specified'
        assert password is not None, 'password must be specified'

        # Status, Kowalski!
        self.v = verbose

        self.protocol = protocol

        self.host = host
        self.port = port

        self.base_url = f'{self.protocol}://{self.host}:{self.port}'

        self.username = username
        self.password = password

        self.access_token = self.authenticate()

        self.headers = {'Authorization': self.access_token}
        self.session = requests.Session()

    # use with "with":
    def __enter__(self):
        # print('Starting')
        return self

    def __exit__(self, *exc):
        # print('Finishing')
        # run shut down procedure
        self.close()
        return False

    def close(self):
        """
            Shutdown session gracefully
        :return:
        """
        try:
            self.session.close()
            return True
        except Exception as e:
            if self.v:
                print(e)
            return False

    def authenticate(self):
        """
            Authenticate user, return access token
        :return:
        """

        # try:
        # post username and password, get access token
        auth = requests.post(f'{self.base_url}/auth',
                             json={"username": self.username, "password": self.password,
                                   "penquins.__version__": __version__})

        if self.v:
            print(auth.json())

        if 'token' not in auth.json():
            print('Authentication failed')
            raise Exception(auth.json()['message'])

        access_token = auth.json()['token']

        if self.v:
            print('Successfully authenticated')

        return access_token


if __name__ == '__main__':
    pass