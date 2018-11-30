import inspect
import json
import shutil
import io
import zipfile
from collections import ChainMap
import pymongo

import flask
import flask_login
import flask_pymongo
from flask_dropzone import Dropzone
# from flask_jwt_extended import JWTManager, jwt_required, jwt_optional, create_access_token, get_jwt_identity
from misaka import Markdown, HtmlRenderer
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from bson.json_util import loads, dumps
from bson import ObjectId
import datetime
import pytz
import logging
from ast import literal_eval
import requests
import numpy as np
import traceback


''' markdown rendering '''
rndr = HtmlRenderer()
md = Markdown(rndr, extensions=('fenced-code',))


def jsonify(data, status=200):
    """
        Replacement for flask.jsonify with custom dumps
    :param data:
    :param status:
    :return:
    """

    return flask.Response(response=dumps(data), status=status, mimetype='application/json')


def get_config(_config_file='/app/config.json'):
    """
        load config data in json format
    """
    try:
        ''' script absolute location '''
        abs_path = os.path.dirname(inspect.getfile(inspect.currentframe()))

        if _config_file[0] not in ('/', '~'):
            if os.path.isfile(os.path.join(abs_path, _config_file)):
                config_path = os.path.join(abs_path, _config_file)
            else:
                raise IOError('Failed to find config file')
        else:
            if os.path.isfile(_config_file):
                config_path = _config_file
            else:
                raise IOError('Failed to find config file')

        with open(config_path) as cjson:
            config_data = json.load(cjson)
            # config must not be empty:
            if len(config_data) > 0:
                return config_data
            else:
                raise Exception('Failed to load config file')

    except Exception as _e:
        print(_e)
        _err = traceback.format_exc()
        print(_err)
        raise Exception('Failed to read in the config file')


def utc_now():
    return datetime.datetime.now(pytz.utc)


def to_pretty_json(value):
    # return dumps(value, indent=4)  # , separators=(',', ': ')
    return dumps(value, separators=(',', ': '))


def init_db():
    _client = pymongo.MongoClient(username=config['database']['admin'],
                                  password=config['database']['admin_pwd'],
                                  host=config['database']['host'],
                                  port=config['database']['port'])
    # _id: db_name.user_name
    user_ids = [_u['_id'] for _u in _client.admin.system.users.find({}, {'_id': 1})]

    db_name = config['database']['db']
    username = config['database']['user']

    # print(f'{db_name}.{username}')
    # print(user_ids)

    if f'{db_name}.{username}' not in user_ids:
        _client[db_name].command('createUser', config['database']['user'],
                                 pwd=config['database']['pwd'], roles=['readWrite'])
        print('Successfully initialized db')


def add_admin():
    """
        Create admin user for the web interface if it does not exists already
    :param _mongo:
    :param _secrets:
    :return:
    """
    ex_admin = mongo.db.users.find_one({'_id': secrets['database']['admin_username']})
    if ex_admin is None or len(ex_admin) == 0:
        try:
            mongo.db.users.insert_one({'_id': secrets['database']['admin_username'],
                                       'password': generate_password_hash(secrets['database']['admin_password']),
                                       'permissions': {},
                                       'last_modified': utc_now()
                                       })
        except Exception as e:
            print(e)
            _err = traceback.format_exc()
            print(_err)


''' load config '''
config = get_config('/app/config.json')

''' load secrets '''
with open('/app/secrets.json') as sjson:
    secrets = json.load(sjson)

''' initialize the Flask app '''
app = flask.Flask(__name__)
# add 'do' statement to jinja environment (does the same as {{ }}, but returns nothing):
app.jinja_env.add_extension('jinja2.ext.do')

# add json prettyfier
app.jinja_env.filters['tojson_pretty'] = to_pretty_json

app.config.update(
    # Flask-Dropzone config:
    DROPZONE_ALLOWED_FILE_TYPE='image',
    DROPZONE_MAX_FILE_SIZE=3,
    DROPZONE_MAX_FILES=5000,
    DROPZONE_IN_FORM=True,
    DROPZONE_UPLOAD_ON_CLICK=True,
    # DROPZONE_UPLOAD_ACTION='handle_upload',  # URL or endpoint
    # DROPZONE_UPLOAD_BTN_ID='submit',
)

dropzone = Dropzone(app)

# set up secret keys:
app.secret_key = config['server']['SECRET_KEY']
app.config['JWT_SECRET_KEY'] = config['server']['SECRET_KEY']

# config db for admin purposes
# mongo_admin = \
#     flask_pymongo.PyMongo(app, uri=f"mongodb://{config['database']['admin']}:{config['database']['admin_pwd']}@" +
#                           f"{config['database']['host']}:{config['database']['port']}/{config['database']['db']}")

# config db for regular use
app.config["MONGO_URI"] = f"mongodb://{config['database']['user']}:{config['database']['pwd']}@" + \
                          f"{config['database']['host']}:{config['database']['port']}/{config['database']['db']}"
mongo = flask_pymongo.PyMongo(app)

# Setup the Flask-JWT-Extended extension
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
# jwt = JWTManager(app)

# session lifetime for registered users
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)

# init admin:
init_db()

# add admin if run first time:
add_admin()

''' login management'''
login_manager = flask_login.LoginManager()
login_manager.init_app(app)


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    select = mongo.db.users.find_one({'_id': username})
    if select is None:
        # return None
        return

    user = User()
    user.id = username
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    # look up in the database
    select = mongo.db.users.find_one({'_id': username})
    if select is None:
        return

    user = User()
    user.id = username

    try:
        user.is_authenticated = check_password_hash(select['password'], flask.request.form['password'])

    except Exception as _e:
        print(_e)
        _err = traceback.format_exc()
        print(_err)
        # return None
        return

    return user


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
        Endpoint for login through the web interface
    :return:
    """
    # print(flask_login.current_user)
    if flask.request.method == 'GET':
        # logged in already?
        if flask_login.current_user.is_authenticated:
            return flask.redirect(flask.url_for('root'))
        # serve template if not:
        else:
            return flask.render_template('template-login.html', logo=config['server']['logo'])
    # print(flask.request.form['username'], flask.request.form['password'])

    # print(flask.request)
    if flask.request.method == 'POST':
        try:
            username = flask.request.json.get('username', None)
            password = flask.request.json.get('password', None)
            if not username:
                return jsonify({"msg": "Missing username parameter"}, status=400)
            if not password:
                return jsonify({"msg": "Missing password parameter"}, status=400)

            # check if username exists and passwords match
            # look up in the database first:
            select = mongo.db.users.find_one({'_id': username})
            if select is not None and check_password_hash(select['password'], password):
                user = User()
                user.id = username

                # # get a JWT token to use API:
                # try:
                #     # post username and password, get access token
                #     auth = requests.post('http://localhost:{}/auth'.format(config['server']['port']),
                #                          json={"username": username, "password": password})
                #     access_token = auth.json()['access_token'] if 'access_token' in auth.json() else 'FAIL'
                # except Exception as e:
                #     print(e)
                #     _err = traceback.format_exc()
                #     print(_err)
                #     access_token = 'FAIL'
                #
                # user.access_token = access_token
                # # print(user, user.id, user.access_token)
                # # save to session:
                # flask.session.permanent = True
                # flask.session['access_token'] = access_token

                flask_login.login_user(user, remember=True)
                # return flask.redirect(flask.url_for('root'))
                return jsonify({'message': 'success'}, status=200)

            else:
                raise Exception('Bad credentials')

        except Exception as _e:
            print(f'Got error: {str(_e)}')
            _err = traceback.format_exc()
            print(_err)
            return jsonify({'message': f'Failed to login user: {_err}'}, status=401)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
        Log user out
    :return:
    """
    # if 'access_token' in flask.session:
    #     flask.session.pop('access_token')
    #     flask.session.modified = True

    flask_login.logout_user()
    return flask.redirect(flask.url_for('root'))


@app.errorhandler(500)
def internal_error(error):
    return '500 error'


@app.errorhandler(404)
def not_found(error):
    return '404 error'


@app.errorhandler(403)
def forbidden(error):
    return '403 error: forbidden'


@login_manager.unauthorized_handler
def unauthorized_handler():
    return flask.redirect(flask.url_for('login'))


# manage users
@app.route('/users', methods=['GET'])
@flask_login.login_required
def manage_users():
    if flask_login.current_user.id == secrets['database']['admin_username']:
        # fetch users from the database:
        _users = {}

        cursor = mongo.db.users.find()
        for usr in cursor:
            # print(usr)
            _users[usr['_id']] = {'permissions': {}}
            for project in usr['permissions']:
                _users[usr['_id']]['permissions'][project] = {}
                _users[usr['_id']]['permissions'][project]['role'] = usr['permissions'][project]['role']
                # _users[usr['_id']]['permissions'][project]['classifications'] = 'NOT DISPLAYED HERE'
        cursor.close()

        return flask.render_template('template-users.html',
                                     user=flask_login.current_user.id,
                                     logo=config['server']['logo'],
                                     users=_users,
                                     current_year=datetime.datetime.now().year)
    else:
        flask.abort(403)


@app.route('/users', methods=['PUT'])
@flask_login.login_required
def add_user():
    """
        Add new user to DB
    :return:
    """
    if flask_login.current_user.id == secrets['database']['admin_username']:
        try:
            username = flask.request.json.get('user', None)
            password = flask.request.json.get('password', None)
            permissions = flask.request.json.get('permissions', '{}')

            if len(username) == 0 or len(password) == 0:
                return 'username and password must be set'

            if len(permissions) == 0:
                permissions = '{}'

            # add user to coll_usr collection:
            mongo.db.users.insert_one(
                {'_id': username,
                 'password': generate_password_hash(password),
                 'permissions': literal_eval(str(permissions)),
                 'last_modified': datetime.datetime.now()}
            )

            return 'success'

        except Exception as _e:
            print(_e)
            _err = traceback.format_exc()
            print(_err)
            return str(_e)
    else:
        flask.abort(403)


@app.route('/users', methods=['POST'])
@flask_login.login_required
def edit_user():
    """
        Edit user info
    :return:
    """

    if flask_login.current_user.id == secrets['database']['admin_username']:
        try:
            _id = flask.request.json.get('_user', None)
            username = flask.request.json.get('edit-user', '')
            password = flask.request.json.get('edit-password', '')
            # permissions = flask.request.json.get('edit-permissions', '{}')

            if _id == secrets['database']['admin_username'] and username != secrets['database']['admin_username']:
                return 'Cannot change the admin username!'

            if len(username) == 0:
                return 'username must be set'

            # change username:
            if _id != username:
                select = mongo.db.users.find_one({'_id': _id})
                select['_id'] = username
                mongo.db.users.insert_one(select)
                mongo.db.users.delete_one({'_id': _id})

            # change password:
            if len(password) != 0:
                result = mongo.db.users.update(
                    {'_id': username},
                    {
                        '$set': {
                            'password': generate_password_hash(password)
                        },
                        '$currentDate': {'last_modified': True}
                    }
                )

            # change permissions:
            # if len(permissions) != 0:
            #     select = mongo.db.users.find_one({'_id': username}, {'_id': 0, 'permissions': 1})
            #     # print(select)
            #     # print(permissions)
            #     _p = literal_eval(str(permissions))
            #     # print(_p)
            #     if str(permissions) != str(select['permissions']):
            #         result = mongo.db.users.update(
            #             {'_id': _id},
            #             {
            #                 '$set': {
            #                     'permissions': _p
            #                 },
            #                 '$currentDate': {'last_modified': True}
            #             }
            #         )

            return 'success'
        except Exception as _e:
            print(_e)
            _err = traceback.format_exc()
            print(_err)
            return str(_e)
    else:
        flask.abort(403)


@app.route('/users', methods=['DELETE'])
@flask_login.login_required
def remove_user():
    """
        Remove user from DB
    :return:
    """
    if flask_login.current_user.id == secrets['database']['admin_username']:
        try:
            # get username from request
            username = flask.request.json.get('user', None)
            if username == secrets['database']['admin_username']:
                return 'Cannot remove the superuser!'

            # try to remove the user:
            mongo.db.users.delete_one({'_id': username})

            return 'success'
        except Exception as _e:
            print(_e)
            _err = traceback.format_exc()
            print(_err)
            return str(_e)
    else:
        flask.abort(403)


# @app.route('/auth', methods=['POST'])
# def auth():
#     """
#         Issue a JSON web token (JWT) for a registered user.
#         To be used with API
#     :return:
#     """
#     try:
#         if not flask.request.is_json:
#             return jsonify({"msg": "Missing JSON in request"}, status=400)
#
#         username = flask.request.json.get('username', None)
#         password = flask.request.json.get('password', None)
#         if not username:
#             return jsonify({"msg": "Missing username parameter"}, status=400)
#         if not password:
#             return jsonify({"msg": "Missing password parameter"}, status=400)
#
#         # check if username exists and passwords match
#         # look up in the database first:
#         select = mongo.db.users.find_one({'_id': username})
#         if select is not None and check_password_hash(select['password'], password):
#             # Identity can be any data that is json serializable
#             access_token = create_access_token(identity=username)
#             return jsonify({'access_token': access_token}, status=200)
#         else:
#             return jsonify({"msg": "Bad username or password"}, status=401)
#
#     except Exception as _e:
#         print(_e)
#         _err = traceback.format_exc()
#         print(_err)
#         return jsonify({"msg": "Something unknown went wrong"}, status=400)


@app.route('/data/<path:filename>')
# @flask_login.login_required
def data_static(filename):
    """
        Get files
    :param filename:
    :return:
    """
    _p, _f = os.path.split(filename)
    print(_p, _f)
    return flask.send_from_directory(os.path.join(config['path']['path_data'], _p), _f)


def stream_template(template_name, **context):
    """
        see: http://flask.pocoo.org/docs/0.11/patterns/streaming/
    :param template_name:
    :param context:
    :return:
    """
    app.update_template_context(context)
    t = app.jinja_env.get_template(template_name)
    rv = t.stream(context)
    rv.enable_buffering(5)
    return rv


@app.route('/', methods=['GET'])
@flask_login.login_required
def root():
    """

    :return:
    """

    ''' web endpoint: home page '''
    user_id = str(flask_login.current_user.id)

    return flask.render_template('template-root.html',
                                 logo=config['server']['logo'],
                                 user=user_id)


@app.route('/docs', defaults={'doc': ''}, methods=['GET'])
@app.route('/docs/<string:doc>', methods=['GET'])
@flask_login.login_required
def docs(doc):
    """

    :return:
    """

    ''' web endpoint: home page '''
    user_id = str(flask_login.current_user.id)

    if len(doc) == 0:
        return flask.render_template('template-docs.html',
                                     logo=config['server']['logo'],
                                     user=user_id)

    else:
        # serve individual docs
        try:
            title = doc.replace('_', ' ').capitalize()

            # render doc with misaka
            with open(os.path.join(config['path']['path_docs'],
                                   doc + '.md'), 'r') as f:
                tut = f.read()

            content = md(tut)

            return flask.Response(stream_template('template-doc.html',
                                                  user=user_id, logo=config['server']['logo'],
                                                  title=title, content=content))

        except Exception as e:
            print(e)
            return flask.render_template('template-docs.html',
                                         logo=config['server']['logo'],
                                         user=user_id)


''' Projects API '''


@app.route('/projects', strict_slashes=False, methods=['GET', 'PUT'])
@app.route('/projects/<string:project_id>', methods=['GET', 'POST', 'DELETE'])
@flask_login.login_required
def projects(project_id=None):

    try:
        user_id = flask_login.current_user.id
        download = flask.request.args.get('download', None, str)

        if flask.request.method == 'GET':

            if project_id is None:
                ''' get/display all projects '''
                # get projects for the user
                user_projects = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                # fetch additional info
                # print(user_projects)
                projects = list(mongo.db.projects.find({'_id': {'$in': list(map(ObjectId, user_projects.keys()))}}))
                # print(projects)
                # append info in place:
                for project in projects:
                    project['_id'] = str(project['_id'])
                    project_id = project['_id']
                    project['role'] = user_projects[project_id]['role']
                    if project['role'] == 'admin':
                        project_users = mongo.db.users.find({f'permissions.{project_id}': {'$exists': True}},
                                                            {'_id': 1, f'permissions.{project_id}.role': 1})
                        project['users'] = dict(ChainMap(*[{pu['_id']: pu['permissions'][f'{project_id}']}
                                                           for pu in project_users]))

                    # datasets:
                    for dataset in project['datasets']:
                        project['datasets'][dataset] = mongo.db.datasets.find_one({'_id': ObjectId(dataset)},
                                                                                  {'_id': 0, 'name': 1,
                                                                                   'description': 1})
                        path_dataset = os.path.join(config['path']['path_data'], 'datasets', dataset)
                        project['datasets'][dataset]['num_files'] = len(next(os.walk(path_dataset))[2]) \
                            if os.path.exists(path_dataset) else 0

                # print(projects)
                if download is None:
                    # web endpoint
                    return flask.render_template('template-projects.html',
                                                 logo=config['server']['logo'],
                                                 user=user_id, add_new=True,
                                                 projects=projects)
                elif download == 'json':
                    # client
                    return jsonify(projects, status=200)

            else:
                ''' get/display single project '''
                _tmp = mongo.db.projects.find_one({'_id': ObjectId(project_id)})
                # print(_tmp)

                if _tmp is not None and len(_tmp) > 0:
                    # check user has access to the project:
                    permissions = mongo.db.users.find_one({'_id': user_id},
                                                          {'_id': 0, 'permissions': 1})['permissions']
                    if project_id in permissions:
                        project_doc = mongo.db.projects.find_one({'_id': ObjectId(project_id)})

                        if project_doc is not None and len(project_doc) > 0:

                            time_tag = utc_now().strftime('%Y%m%d_%H%M%S') + 'Z'

                            project = project_doc

                            project['_id'] = str(project['_id'])
                            project['time_tag'] = time_tag

                            project_id = project['_id']
                            project['role'] = permissions[project_id]['role']
                            if project['role'] == 'admin':
                                project_users = mongo.db.users.find({f'permissions.{project_id}': {'$exists': True}},
                                                                    {'_id': 1, f'permissions.{project_id}.role': 1})
                                project['users'] = dict(ChainMap(*[{pu['_id']: pu['permissions'][f'{project_id}']}
                                                                   for pu in project_users]))

                            # datasets:
                            for dataset in project['datasets']:
                                project['datasets'][dataset] = mongo.db.datasets.find_one({'_id': ObjectId(dataset)},
                                                                                          {'_id': 0, 'name': 1,
                                                                                           'description': 1})
                                path_dataset = os.path.join(config['path']['path_data'], 'datasets', dataset)
                                project['datasets'][dataset]['num_files'] = len(next(os.walk(path_dataset))[2]) \
                                    if os.path.exists(path_dataset) else 0

                            if download == 'json':
                                # json:
                                response = jsonify(project, status=200)
                                response.headers['Content-Disposition'] = f'attachment;filename={project_id}.json'
                                return response

                            else:
                                # web end-point: display single project
                                return flask.render_template('template-projects.html',
                                                             logo=config['server']['logo'],
                                                             user=user_id, add_new=False,
                                                             projects=[project])
                        else:
                            response = flask.jsonify({'status': 'failed',
                                                      'message': f'project {project_id} not found'}), 500
                            return response
                    else:
                        response = flask.jsonify({'status': 'failed',
                                                  'message': f'access to {project_id} denied'}), 403
                        return response
                else:
                    response = flask.jsonify({'status': 'failed',
                                              'message': f'project {project_id} not found'}), 500
                    return response

        ''' Add project '''
        if flask.request.method == 'PUT':

            # print(flask.request.json)
            name = flask.request.json.get('name', None)
            description = flask.request.json.get('description', '')
            classes = flask.request.json.get('classes', '')

            if (len(name) == 0) or (len(description) == 0) or (len(classes) == 0):
                return jsonify({'status': 'failed', 'message': 'all fields are compulsory'}, 400)

            classes = sorted(list(set(classes.split())))

            # add to db:
            project_id = mongo.db.projects.insert_one(
                {'name': name,
                 'description': description,
                 'classes': classes,
                 'datasets': {},
                 'last_modified': datetime.datetime.now()}
            )
            # print(project_id.inserted_id)

            mongo.db.users.update_one(
                {'_id': user_id},
                {'$set': {
                    f'permissions.{project_id.inserted_id}': {
                        'role': 'admin',
                        'classifications': {}
                    }
                }}
            )

            return jsonify({'status': 'success', 'project_id': str(project_id.inserted_id)}, 200)

        ''' Delete project '''
        if flask.request.method == 'DELETE':
            # get project_id from request
            # project_id = flask.request.json.get('project_id', None)

            if project_id is not None:
                _tmp = mongo.db.projects.find_one({'_id': ObjectId(project_id)})
                # print(_tmp)

                if _tmp is not None and len(_tmp) > 0:
                    # check user is admin for the project:
                    permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                    if project_id in permissions:
                        if permissions[project_id]['role'] == 'admin':
                            # try to remove the project:
                            mongo.db.projects.delete_one({'_id': ObjectId(project_id)})

                            # clean up datasets:
                            dataset_ids = mongo.db.datasets.find({'project_id': ObjectId(project_id)},
                                                                 {'_id': 1})
                            # print(list(dataset_ids))
                            for ds in dataset_ids:
                                # delete files:
                                path_dataset = os.path.join(config['path']['path_data'], 'datasets', str(ds['_id']))
                                try:
                                    shutil.rmtree(path_dataset)
                                except Exception as e:
                                    print(str(e))
                                    _err = traceback.format_exc()
                                    print(_err)

                            mongo.db.datasets.delete_many({'project_id': ObjectId(project_id)})

                            # clean up users:
                            mongo.db.users.update(
                                {f'permissions.{project_id}': {'$exists': True}},
                                {'$unset': {
                                    f'permissions.{project_id}': ''
                                }},
                                multi=True
                            )

                            return jsonify({'status': 'success'}, 200)
                        else:
                            flask.abort(403)
                            # return f'user {user_id} is not admin for project_id {project_id}'
                    else:
                        flask.abort(403)
                        # return f'user {user_id} not on project_id {project_id}'

                else:
                    return jsonify({'status': 'failed', 'message': f'project_id {project_id} not found'}, 400)
            else:
                return jsonify({'status': 'failed', 'message': 'project_id not defined'}, 400)

        ''' Modify project '''
        if flask.request.method == 'POST':

            if project_id is not None:

                _tmp = mongo.db.projects.find_one({'_id': ObjectId(project_id)})
                # print(_tmp)

                if _tmp is not None and len(_tmp) > 0:

                    # check user is admin for the project:
                    permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                    if project_id in permissions:
                        if permissions[project_id]['role'] == 'admin':

                            # print(flask.request.json)
                            add_user = flask.request.json.get('add_user', None)
                            add_user_role = flask.request.json.get('add_user_role', None)
                            add_classes = flask.request.json.get('classes', None)

                            remove_user = flask.request.json.get('remove_user', None)
                            # TODO:
                            remove_class = flask.request.json.get('remove_class', None)

                            edit_name = flask.request.json.get('name', None)
                            edit_description = flask.request.json.get('description', None)

                            # editing project metadata?
                            if (edit_name is not None) and (edit_description is not None):
                                if (len(edit_name) == 0) or (len(edit_description) == 0):
                                    return jsonify({'status': 'failed', 'message': 'all fields are compulsory'}, 400)

                                # edit in db:
                                project_id = mongo.db.projects.update_one(
                                    {'_id': ObjectId(project_id)},
                                    {'$set': {'name': edit_name,
                                              'description': edit_description,
                                              'last_modified': datetime.datetime.now()}}
                                )

                            # adding class(es)?
                            if add_classes is not None:

                                if len(add_classes) == 0:
                                    return jsonify({'status': 'failed', 'message': 'classes must be set'}, 400)

                                classes = add_classes.split()

                                classes_old = mongo.db.projects.find_one({'_id': ObjectId(project_id)},
                                                                         {'_id': 0, 'classes': 1})['classes']

                                classes = sorted(list(set(classes + classes_old)))

                                mongo.db.projects.update_one(
                                    {'_id': ObjectId(project_id)},
                                    {'$set': {
                                        'classes': classes
                                    }}
                                )

                            # adding user?
                            if add_user is not None and add_user_role is not None:
                                if add_user_role not in ('user', 'admin'):
                                    return jsonify({'status': 'failed',
                                                    'message': f'role {add_user_role} not recognized'}, 400)
                                _tmp = mongo.db.users.find_one({'_id': add_user}, {'_id': 1})
                                if _tmp is not None and len(_tmp) > 0:
                                    # check if user already assigned to project:
                                    # check if username already exists:
                                    select = mongo.db.users.find_one({'_id': add_user,
                                                                      f'permissions.{project_id}': {'$exists': True}},
                                                                     {'_id': 1})
                                    if select is not None and len(select) > 0:
                                        return jsonify({'status': 'failed',
                                                        'message':
                                                            f'user {add_user} already assigned to project {project_id}'},
                                                       400)

                                    mongo.db.users.update_one(
                                        {'_id': add_user},
                                        {'$set': {
                                            f'permissions.{project_id}': {'role': add_user_role,
                                                                          'classifications': {}}
                                        }}
                                    )
                                else:
                                    return jsonify({'status': 'failed', 'message': f'user {add_user} not found'}, 400)

                            # removing user?
                            if remove_user is not None:
                                # print(remove_user)
                                _tmp = mongo.db.users.find_one({'_id': remove_user}, {'_id': 1})
                                if _tmp is not None and len(_tmp) > 0:
                                    if remove_user == user_id:
                                        return jsonify({'status': 'failed', 'message': 'cannot remove thyself!'}, 400)

                                    mongo.db.users.update_one(
                                        {'_id': remove_user},
                                        {'$unset': {
                                            f'permissions.{project_id}': ''
                                        }}
                                    )

                                else:
                                    return jsonify({'status': 'failed', 'message': f'user {remove_user} not found'},
                                                   400)

                            return jsonify({'status': 'success'}, 200)
                        else:
                            flask.abort(403)
                            # return f'user {user_id} is not admin for project_id {project_id}'
                    else:
                        flask.abort(403)
                        # return f'user {user_id} not on project_id {project_id}'

                else:
                    return f'project_id {project_id} not found'

            else:
                return 'project_id not defined'

    except Exception as _e:
        # FIXME: this is for debugging
        print(_e)
        _err = traceback.format_exc()
        print(_err)
        return jsonify({'status': 'failed', 'message': _err}, 500)


''' Datasets API '''


@app.route('/projects/<string:project_id>/datasets', strict_slashes=False, methods=['GET', 'PUT'])
@app.route('/projects/<string:project_id>/datasets/<string:dataset_id>', methods=['GET', 'POST', 'DELETE'])
@flask_login.login_required
def datasets(project_id, dataset_id=None):

    try:
        user_id = flask_login.current_user.id

        ''' web endpoint '''
        if flask.request.method == 'GET':
            if dataset_id is None:
                # TODO: display all datasets for project
                return flask.redirect(flask.url_for('root'))
            else:
                # download dataset as archive:
                download = flask.request.args.get('download', None, str)
                download_format = flask.request.args.get('format', None, str)
                if (download is not None) and (download_format is not None):
                    if download == 'dataset':
                        if download_format == 'zip':
                            path_dataset = os.path.join(config['path']['path_data'], 'datasets', dataset_id)

                            zip_io = io.BytesIO()
                            with zipfile.ZipFile(zip_io, mode='w', compression=zipfile.ZIP_DEFLATED) as backup_zip:
                                for root, dirs, files in os.walk(path_dataset):
                                    for file in files:
                                        backup_zip.write(os.path.join(root, file), file)

                            time_tag = utc_now().strftime('%Y%m%d_%H%M%S')
                            return flask.Response(zip_io.getvalue(),
                                                  mimetype='application/zip',
                                                  headers={'Content-Disposition':
                                                           f'attachment;filename={dataset_id}.{time_tag}.zip'})
                        else:
                            return jsonify({'status': 'failed', 'message': 'unknown format'}, status=400)

                    elif download == 'classifications':
                        if download_format == 'json':
                            classifications = mongo.db.users.find_one({'_id': user_id,
                                                   f'permissions.{project_id}.classifications.{dataset_id}':
                                                       {'$exists': True}},
                                              {'_id': 0, f'permissions.{project_id}.classifications.{dataset_id}': 1})
                            if len(classifications) > 0:
                                classifications = \
                                    classifications['permissions'][project_id]['classifications'][dataset_id]
                            else:
                                classifications = {}

                            time_tag = utc_now().strftime('%Y%m%d_%H%M%S')

                            response = jsonify(classifications, status=200)

                            response.headers['Content-Disposition'] = \
                                f'attachment;filename={dataset_id}.{time_tag}.json'

                            return response
                        else:
                            return jsonify({'status': 'failed', 'message': 'unknown format'}, status=400)

                    else:
                        return jsonify({'status': 'failed', 'message': 'bad download request'}, status=400)

                # TODO: display single dataset
                return flask.redirect(flask.url_for('root'))

        ''' Add dataset '''
        if flask.request.method == 'PUT':
            # check user is admin for the project:
            permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
            if project_id in permissions:
                if permissions[project_id]['role'] == 'admin':
                    # print(flask.request.json)
                    name = flask.request.json.get('name', '')
                    description = flask.request.json.get('description', '')

                    if (len(name) == 0) or (len(description) == 0):
                        return jsonify({'status': 'failed', 'message': 'all fields are compulsory'}, status=400)

                    # add to db:
                    dataset_inserted = mongo.db.datasets.insert_one(
                        {'name': name,
                         'description': description,
                         'project_id': ObjectId(project_id),
                         # 'files': {},  # TODO? push file names here as they get uploaded?
                         'last_modified': datetime.datetime.now()}
                    )

                    mongo.db.projects.update_one(
                        {'_id': ObjectId(project_id)},
                        {'$set': {
                            f'datasets.{dataset_inserted.inserted_id}': {}
                        }}
                    )

                    # mkdir
                    path_dataset = os.path.join(config['path']['path_data'], 'datasets',
                                                str(dataset_inserted.inserted_id))
                    if not os.path.exists(path_dataset):
                        os.makedirs(path_dataset)

                    # return dataset_id
                    return flask.jsonify({'status': 'success', 'dataset_id': str(dataset_inserted.inserted_id)})

                else:
                    flask.abort(403)
                    # return f'user {user_id} is not admin for project_id {project_id}'
            else:
                flask.abort(403)
                # return f'user {user_id} not on project_id {project_id}'

        ''' Modify dataset (upload files) '''
        if flask.request.method == 'POST':
            if dataset_id is not None:

                _tmp = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
                # print(_tmp)

                if _tmp is not None and len(_tmp) > 0:
                    # print('GETTING FILES')
                    # not sure why I did it this way :)
                    # print(flask.request.form['dataset_id'])
                    # dataset_id_post = flask.request.form['dataset_id']
                    dataset_id_post = dataset_id
                    path_save = os.path.join(config['path']['path_data'], 'datasets', dataset_id_post)
                    if not os.path.exists(path_save):
                        os.makedirs(path_save)

                    # print(flask.request.files)
                    for key, f in flask.request.files.items():
                        if key.startswith('file'):
                            print(f.filename)
                            # save file:
                            f.save(os.path.join(path_save, f.filename))
                    return jsonify({'status': 'success'}, status=204)

                else:
                    return jsonify({'status': 'failed', 'message': f'dataset_id {dataset_id} not found'}, status=400)

            else:
                return jsonify({'status': 'failed', 'message': 'dataset_id not defined'}, status=400)

        ''' Delete dataset '''
        if flask.request.method == 'DELETE':

            if dataset_id is not None:
                _tmp = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
                # print(_tmp)

                if _tmp is not None and len(_tmp) > 0:
                    # check user is admin for the project:
                    permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                    if project_id in permissions:
                        if permissions[project_id]['role'] == 'admin':

                            # delete dataset:
                            mongo.db.datasets.delete_one({'_id': ObjectId(dataset_id)})

                            # delete files:
                            path_dataset = os.path.join(config['path']['path_data'], 'datasets', dataset_id)
                            try:
                                shutil.rmtree(path_dataset)
                            except Exception as e:
                                print(str(e))
                                _err = traceback.format_exc()
                                print(_err)

                            # clean up projects:
                            mongo.db.projects.update_one(
                                {'_id': ObjectId(project_id)},
                                {'$unset': {
                                    f'datasets.{dataset_id}': ''
                                }}
                            )

                            return jsonify({'status': 'success'}, 200)
                        else:
                            flask.abort(403)
                            # return f'user {user_id} is not admin for project_id {project_id}'
                    else:
                        flask.abort(403)
                        # return f'user {user_id} not on project_id {project_id}'

                else:
                    return jsonify({'status': 'failed', 'message': f'dataset_id {dataset_id} not found'}, status=400)
            else:
                return jsonify({'status': 'failed', 'message': 'dataset_id not defined'}, status=400)

    except Exception as _e:
        # FIXME: this is for debugging
        print(_e)
        _err = traceback.format_exc()
        print(_err)
        return jsonify({'status': 'failed', 'message': _err}, status=500)


@app.route('/projects/<string:project_id>/datasets/<string:dataset_id>/classify', methods=['GET', 'POST', 'DELETE'])
@flask_login.login_required
def datasets_classify(project_id, dataset_id):

    def find_files(_path_dataset, _classifications):
        for dir_name, subdir_list, file_list in os.walk(_path_dataset, followlinks=True):
            for fname in file_list:
                if fname.endswith('.jpg') or fname.endswith('.png'):
                    if fname in _classifications:
                        yield {fname: _classifications[fname]}
                    else:
                        yield {fname: []}

    try:
        user_id = flask_login.current_user.id

        ''' web endpoint '''
        if flask.request.method == 'GET':

            dataset = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
            # print(_tmp)

            if dataset is not None and len(dataset) > 0:
                # check user has access to the project:
                permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                if project_id in permissions:

                    classes = mongo.db.projects.find_one({'_id': ObjectId(project_id)},
                                                         {'_id': 0, 'classes': 1})['classes']

                    classifications = permissions[project_id]['classifications'][dataset_id] \
                            if dataset_id in permissions[project_id]['classifications'] else {}
                    # classifications = {'strkid5891521828150037_pid589152182815_scimref.jpg': ['streak']}

                    path_dataset = os.path.join(config['path']['path_data'], 'datasets', dataset_id)

                    return flask.Response(stream_template('template-dataset.html',
                                                          logo=config['server']['logo'],
                                                          user=user_id,
                                                          inspect=False,
                                                          project_id=project_id,
                                                          dataset_id=dataset_id,
                                                          dataset=dataset,
                                                          classes=classes,
                                                          classifications=find_files(path_dataset, classifications)))

                else:
                    flask.abort(403)

            else:
                return f'project_id {project_id} not found'

        ''' Save classifications '''
        if flask.request.method == 'POST':

            _tmp = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
            # print(_tmp)

            if _tmp is not None and len(_tmp) > 0:
                classifications = json.loads(flask.request.get_data())
                # print(classifications)
                classifications = {k: v for k, v in classifications.items() if len(v) > 0}

                # dump to db:
                mongo.db.users.update_one(
                    {'_id': user_id},
                    {'$set': {
                        f'permissions.{project_id}.classifications.{dataset_id}': classifications
                    }}
                )

                # date = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                # with open(f'/Users/dmitryduev/_caltech/python/deep-asteroids/data-raw/zooniverse.{date}.json',
                #           'w') as f:
                #     json.dump(classifications, f, indent=2)
                return 'success'

            else:
                return f'dataset_id {dataset_id} not found'

        ''' Reset classifications '''
        if flask.request.method == 'DELETE':

            _tmp = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
            # print(_tmp)

            if _tmp is not None and len(_tmp) > 0:
                # check user has access to the project:
                permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                if project_id in permissions:

                    # reset:
                    mongo.db.users.update_one(
                        {'_id': user_id},
                        {'$set': {
                            f'permissions.{project_id}.classifications.{dataset_id}': {}
                        }}
                    )

                    return 'success'

                else:
                    flask.abort(403)
                    # return f'user {user_id} not on project_id {project_id}'

            else:
                return f'dataset_id {dataset_id} not found'

    except Exception as _e:
        # FIXME: this is for debugging
        print(_e)
        _err = traceback.format_exc()
        print(_err)
        return jsonify({'status': 'failed', 'message': _err}, status=500)


@app.route('/projects/<string:project_id>/datasets/<string:dataset_id>/inspect', methods=['GET', 'POST'])
@flask_login.login_required
def datasets_inspect(project_id, dataset_id):

    def find_files(_path_dataset, _classifications):
        for dir_name, subdir_list, file_list in os.walk(_path_dataset, followlinks=True):
            for fname in file_list:
                if fname.endswith('.jpg') or fname.endswith('.png'):
                    if fname in _classifications:
                        yield {fname: _classifications[fname]}
                    else:
                        yield {fname: []}

    try:
        user_id = flask_login.current_user.id

        ''' web endpoint '''
        if flask.request.method == 'GET':

            dataset = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
            # print(_tmp)

            if dataset is not None and len(dataset) > 0:
                # check user has access to the project:
                permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                if project_id in permissions:

                    classes = mongo.db.projects.find_one({'_id': ObjectId(project_id)},
                                                         {'_id': 0, 'classes': 1})['classes']

                    # classifications = permissions[project_id]['classifications'][dataset_id] \
                    #         if dataset_id in permissions[project_id]['classifications'] else {}
                    # classifications = {'strkid5891521828150037_pid589152182815_scimref.jpg': ['streak']}

                    c = mongo.db.users.find({f'permissions.{project_id}.classifications.{dataset_id}':
                                                 {'$exists': True}},
                                            {f'permissions.{project_id}.classifications.{dataset_id}': 1})
                    classifications = dict()
                    for cc in c:
                        _c = cc['permissions'][project_id]['classifications'][dataset_id]
                        for _cc in _c:
                            if _cc not in classifications:
                                classifications[_cc] = _c[_cc]
                            else:
                                classifications[_cc] += _c[_cc]
                    # print(classifications)

                    path_dataset = os.path.join(config['path']['path_data'], 'datasets', dataset_id)

                    return flask.Response(stream_template('template-dataset.html',
                                                          logo=config['server']['logo'],
                                                          user=user_id,
                                                          inspect=True,
                                                          project_id=project_id,
                                                          dataset_id=dataset_id,
                                                          dataset=dataset,
                                                          classes=classes,
                                                          classifications=find_files(path_dataset, classifications)))

                else:
                    flask.abort(403)

            else:
                return f'project_id {project_id} not found'

        ''' Save classifications '''
        if flask.request.method == 'POST':

            _tmp = mongo.db.datasets.find_one({'_id': ObjectId(dataset_id)})
            # print(_tmp)

            if _tmp is not None and len(_tmp) > 0:
                classifications = json.loads(flask.request.get_data())
                classifications = {k: v for k, v in classifications.items() if len(v) > 0}

                # dump to db:
                mongo.db.users.update_one(
                    {'_id': user_id},
                    {'$set': {
                        f'permissions.{project_id}.classifications.{dataset_id}': classifications
                    }}
                )

                return 'success'

            else:
                return f'dataset_id {dataset_id} not found'

    except Exception as _e:
        # FIXME: this is for debugging
        print(_e)
        _err = traceback.format_exc()
        print(_err)
        return jsonify({'status': 'failed', 'message': _err}, status=500)


if __name__ == '__main__':
    app.run(host=config['server']['host'], port=config['server']['port'], threaded=True)
