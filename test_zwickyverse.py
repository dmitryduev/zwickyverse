from zwickyverse import Private
import os
import glob


class TestZwickyverse(object):

    # remember to escape special chars in password!
    # python -m pytest test_zwickyverse.py --username=admin --password=
    # python -m pytest -s test_zwickyverse.py --username=admin --password=
    # python -m pytest -q test_zwickyverse.py --username=admin --password=

    def test_authenticate(self, username, password):
        # if authentication fails, exception will be raised
        with Private(username=username, password=password) as p:
            pass

    def test_api(self, username, password):
        # with Private(protocol='http', host='127.0.0.1', port=8000, username='admin', password='admin', verbose=True) as p:
        with Private(username=username, password=password, verbose=True) as p:
            # get metadata of all projects
            projects = p.get_project()
            print(projects)

            if len(projects) > 0:
                # get metadata for a single project
                p_id = projects[0]['_id']
                project = p.get_project(project_id=p_id)
                print(project)

                if len(projects[0]['datasets']) > 0:
                    # get classifications for single dataset from this project
                    ds_id = list(projects[0]['datasets'].keys())[0]
                    ds = p.get_classifications(project_id=p_id, dataset_id=ds_id)
                    # get classifications for all datasets from this project
                    # ds = p.get_classifications(project_id=ztf['_id'])
                    print(ds)

            # add project
            p_id = p.add_project(name='Streaks', description='Example streaks', classes=('keep', 'ditch'))
            print(f'created project: {p_id}')

            # add dataset to the newly created project
            path = os.path.abspath('./dev')
            images = glob.glob(os.path.join(path, '*.jpg'))  # image absolute paths
            print(images)
            ds_id = p.add_dataset(project_id=p_id, name='Reals', description='Short streaks', files=images)
            print(f'created dataset in project {p_id}: {ds_id}')
