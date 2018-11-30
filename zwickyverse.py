# import string
# import random
import traceback
import os
# from copy import deepcopy
from typing import Union
import requests
import glob
from bson.json_util import loads


''' Zwickyverse: simplifying and accelerating data-set labeling for machine learning activities '''
__version__ = '0.1.0'


Num = Union[int, float]
QueryPart = Union['task', 'result']
Items = Union[list, tuple, set]


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

    def add_project(self, name: str, description: str, classes: Items, timeout: Num = 10) -> str:
        """

        :param name:
        :param description:
        :param classes:
        :param timeout:
        :return: created project_id
        """
        url = os.path.join(self.base_url, 'projects')

        cs = ' '.join(classes)
        resp = self.session.put(url=url, json={'name': name,
                                               'description': description,
                                               'classes': cs},
                                timeout=timeout)
        return resp.json()['project_id']

    def edit_project(self, project_id: str, timeout: Num = 10):
        """

        :param project_id:
        :param timeout:
        :return:
        """
        raise NotImplementedError()

    def delete_project(self, project_id: str, timeout: Num = 10):
        """

        :param project_id:
        :param timeout:
        :return:
        """
        raise NotImplementedError()

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

    def add_dataset(self, project_id: str, name: str, description: str, files: Items, timeout: Num = 10) -> str:
        """

        :param project_id:
        :param name:
        :param description:
        :param files: file paths
        :param timeout:
        :return: created project_id
        """
        url = os.path.join(self.base_url, 'projects', project_id, 'datasets')

        # create dataset
        resp = self.session.put(url=url, json={'name': name, 'description': description}, timeout=timeout)
        dataset_id = resp.json()['dataset_id']

        # upload files
        if len(files) > 0:
            fs = {'file_' + os.path.basename(fl): open(fl, 'rb') for fl in files}
            # print(fs)
            url_dataset = os.path.join(self.base_url, 'projects', project_id, 'datasets', dataset_id)
            resp = self.session.post(url_dataset, files=fs)
            # print(resp)
            # print(resp.text)

            # if resp.json()['status'] == 'success':
            #     return dataset_id
            # else:
            #     raise Exception(resp.json()['message'])
        return dataset_id
