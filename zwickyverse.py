import string
import random
import traceback
import os
from copy import deepcopy
from typing import Union
import requests
from bson.json_util import loads


''' Zwickyverse: simplifying and accelerating data-set labeling for machine learning activities '''
__version__ = '0.1.0'


Num = Union[int, float]
QueryPart = Union['task', 'result']


class Private(object):
    """
        Zwickyverse client
    """

    def __init__(self, protocol='https', host='private.caltech.edu', port=443, verbose=False,
                 username=None, password=None):

        assert username is not None, 'username must be specified'
        assert password is not None, 'password must be specified'

        # Status, Private!
        self.v = verbose

        self.protocol = protocol

        self.host = host
        self.port = port

        self.base_url = f'{self.protocol}://{self.host}:{self.port}'

        self.username = username
        self.password = password

        self.session = requests.Session()
        self.authenticate()

        # self.headers = {'Authorization': self.access_token}

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
        auth = self.session.post(os.path.join(self.base_url, 'login'),
                                 json={"username": self.username, "password": self.password,
                                       "zwickyverse.__version__": __version__})

        resp = auth.json()
        if 'message' in resp and resp['message'] == 'success':
            if self.v:
                print('Successfully authenticated')

        else:
            msg = resp['message'] if 'message' in resp else 'unknown error'
            raise Exception(f'Authentication error: {msg}')

    def get_project(self, project_id: str='all', timeout: Num=10):
        """
            Get project(s) metadata
        :param project_id:
        :param timeout:
        :return:
        """

        url = os.path.join(self.base_url, 'projects') \
            if project_id == 'all' else os.path.join(self.base_url, 'projects', project_id)
        resp = self.session.get(url=url, params={'download': 'json'}, timeout=timeout)

        # should return either list of projects or dict with single project
        return resp.json()

    def get_classifications(self, project_id: str, dataset_id: str='all', timeout: Num=60):
        """
            Get project(s) metadata
        :param project_id:
        :param dataset_id:
        :param timeout:
        :return:
        """

        url_proj = os.path.join(self.base_url, 'projects', project_id)

        if dataset_id != 'all':
            # get classifications for dataset
            url = os.path.join(url_proj, 'datasets', dataset_id)
            resp = self.session.get(url=url, params={'download': 'classifications', 'format': 'json'},
                                    timeout=timeout)
            try:
                dataset = resp.json()
            except Exception as e:
                if self.v:
                    print(e)
                    _err = traceback.format_exc()
                    print(_err)
                dataset = {}

            return dataset

        else:
            # get classifications for all project's datasets
            # get project first:
            resp = self.session.get(url=url_proj, params={'download': 'json'}, timeout=timeout)
            project = resp.json()

            datasets = {}
            for d_id in project['datasets']:
                url = os.path.join(url_proj, 'datasets', d_id)
                resp = self.session.get(url=url, params={'download': 'classifications', 'format': 'json'},
                                        timeout=timeout)
                try:
                    dataset = resp.json()
                except Exception as e:
                    if self.v:
                        print(e)
                        _err = traceback.format_exc()
                        print(_err)
                    dataset = {}
                datasets[d_id] = dataset

            return datasets


if __name__ == '__main__':

    with Private(protocol='http', host='127.0.0.1', port=8000, username='admin', password='admin', verbose=True) as p:

        projects = p.get_project()
        print(projects)

        ztf = p.get_project(project_id='5bdbe9f13610a1000f76abca')
        print(ztf)

        ds = p.get_classifications(project_id=ztf['_id'], dataset_id='5bdbea1b3610a10014de7fc3')
        # ds = p.get_classifications(project_id=ztf['_id'])
        print(ds)
