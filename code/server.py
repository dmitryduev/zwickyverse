import inspect
import json
from collections import ChainMap
import pymongo

import flask
import flask_login
import flask_pymongo
from flask_jwt_extended import JWTManager, jwt_required, jwt_optional, create_access_token, get_jwt_identity
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
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
jwt = JWTManager(app)

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

    username = flask.request.form['username']
    password = flask.request.form['password']
    # check if username exists and passwords match
    # look up in the database first:
    select = mongo.db.users.find_one({'_id': username})
    if select is not None and check_password_hash(select['password'], password):
        user = User()
        user.id = username

        # get a JWT token to use API:
        try:
            # post username and password, get access token
            auth = requests.post('http://localhost:{}/auth'.format(config['server']['port']),
                                 json={"username": username, "password": password})
            access_token = auth.json()['access_token'] if 'access_token' in auth.json() else 'FAIL'
        except Exception as e:
            print(e)
            access_token = 'FAIL'

        user.access_token = access_token
        # print(user, user.id, user.access_token)
        # save to session:
        flask.session.permanent = True
        flask.session['access_token'] = access_token

        flask_login.login_user(user, remember=True)
        return flask.redirect(flask.url_for('root'))
    else:
        # serve template with flag fail=True to display fail message
        return flask.render_template('template-login.html', logo=config['server']['logo'],
                                     messages=[(u'Failed to log in.', u'danger')])


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """
        Log user out
    :return:
    """
    if 'access_token' in flask.session:
        flask.session.pop('access_token')
        flask.session.modified = True

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
            _users[usr['_id']] = {'permissions': usr['permissions']}
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
            id = flask.request.json.get('_user', None)
            username = flask.request.json.get('edit-user', '')
            password = flask.request.json.get('edit-password', '')
            permissions = flask.request.json.get('edit-permissions', '{}')

            if id == secrets['database']['admin_username'] and username != secrets['database']['admin_username']:
                return 'Cannot change the admin username!'

            if len(username) == 0:
                return 'username must be set'

            # change username:
            if id != username:
                select = mongo.db.users.find_one({'_id': id})
                select['_id'] = username
                mongo.db.users.insert_one(select)
                mongo.db.users.delete_one({'_id': id})

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
            if len(permissions) != 0:
                select = mongo.db.users.find_one({'_id': username}, {'_id': 0, 'permissions': 1})
                # print(select)
                # print(permissions)
                _p = literal_eval(str(permissions))
                # print(_p)
                if str(permissions) != str(select['permissions']):
                    result = mongo.db.users.update(
                        {'_id': id},
                        {
                            '$set': {
                                'permissions': _p
                            },
                            '$currentDate': {'last_modified': True}
                        }
                    )

            return 'success'
        except Exception as _e:
            print(_e)
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
            return str(_e)
    else:
        flask.abort(403)


@app.route('/auth', methods=['POST'])
def auth():
    """
        Issue a JSON web token (JWT) for a registered user.
        To be used with API
    :return:
    """
    try:
        if not flask.request.is_json:
            return flask.jsonify({"msg": "Missing JSON in request"}), 400

        username = flask.request.json.get('username', None)
        password = flask.request.json.get('password', None)
        if not username:
            return flask.jsonify({"msg": "Missing username parameter"}), 400
        if not password:
            return flask.jsonify({"msg": "Missing password parameter"}), 400

        # check if username exists and passwords match
        # look up in the database first:
        select = mongo.db.users.find_one({'_id': username})
        if select is not None and check_password_hash(select['password'], password):
            # Identity can be any data that is json serializable
            access_token = create_access_token(identity=username)
            return flask.jsonify(access_token=access_token), 200
        else:
            return flask.jsonify({"msg": "Bad username or password"}), 401

    except Exception as _e:
        print(_e)
        return flask.jsonify({"msg": "Something unknown went wrong"}), 400


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


@app.route('/', methods=['GET', 'POST'])
def root():
    if flask_login.current_user.is_anonymous:
        user_id = None
    else:
        user_id = str(flask_login.current_user.id)

    if flask.request.method == 'GET':
        # do not display anything for the anonymous
        if user_id is None:
            return flask.render_template('template-root.html',
                                         user=user_id,
                                         logo=config['server']['logo'],
                                         projects=None)
        else:
            # TODO: get projects for the user
            user_projects = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
            # fetch additional info
            print(user_projects)
            projects = list(mongo.db.projects.find({'_id': {'$in': list(map(ObjectId, user_projects.keys()))}}))
            # print(projects)
            # append info in place:
            for project in projects:
                project_id = str(project['_id'])
                project['role'] = user_projects[project_id]['role']
                if project['role'] == 'admin':
                    project_users = mongo.db.users.find({f'permissions.{project_id}': {'$exists': True}},
                                                        {'_id': 1, f'permissions.{project_id}.role': 1})
                    project['users'] = dict(ChainMap(*[{pu['_id']: pu['permissions'][f'{project_id}']}
                                                       for pu in project_users]))

            # for user_project in user_projects:
            print(projects)

            # TODO: superusers can see and do everything
            # otherwise, there are two roles: admin and user
            _projects = {'5b9236ae497dcf000c154a1d': {'name': 'project1',
                                'description': 'Lorem ipsum dolor sit amet',
                                'datasets': {'dataset1': {
                                                 'description': 'Omnia mea mecum porto',
                                                 'data': ['file1.jpg', 'file2.jpg', 'file3.jpg', 'file4.jpg']},
                                             'dataset2': {
                                                 'description': 'Sic transit glori mundi',
                                                 'data': ['file1.jpg']}
                                             },
                                'classes': ['class1', 'class2', 'class3'],
                                'users': [{'user1': {'role': 'admin'}},
                                          {'user2': {'role': 'user'}},
                                          {'user3': {'role': 'user'}}],
                                'role': 'admin'
                                },
                        'id2': {'name': 'project2',
                                'description': 'Lorem ipsum dolor sit amet',
                                'datasets': {'dataset1': {
                                    'description': None,
                                    'data': ['file1.jpg', 'file2.jpg']}
                                },
                                'classes': ['class1', 'class2'],
                                'role': 'user'
                                }
                        }

            return flask.render_template('template-root.html',
                                         logo=config['server']['logo'],
                                         user=user_id,
                                         projects=projects)

    classes = {
        0: "Plausible Asteroid (short streak)",
        1: "Satellite (long streak - could be partially masked)",
        2: "Masked bright star",
        3: "Dementors and ghosts",
        4: "Cosmic rays",
        5: "Yin-Yang (multiple badly subtracted stars)",
        6: "Satellite flashes",
        7: "Skip (Includes 'Not Sure' and seemingly 'Blank Images')"
    }

    if flask.request.method == 'GET':
        return flask.render_template('template-root.html',
                                     user=user_id,
                                     logo=config['server']['logo'],
                                     cutouts={'1': ['a']}, classes=list(classes.values()))

    # TODO: get latest json
    with open('/Users/dmitryduev/_caltech/python/deep-asteroids/data-raw/zooniverse.20180822.json', 'r') as f:
        classifications_raw = json.load(f)

    if flask.request.method == 'GET':
        classifications = dict()
        # i = 0
        for crk, crv in classifications_raw.items():
            if os.path.exists(os.path.join('/Users/dmitryduev/_caltech/python/deep-asteroids/data-raw/zooniverse',
                                           crk)):
                classifications[crk] = crv
            #     i += 1
            # if i > 4:
            #     break

        return flask.render_template('template-root.html', logo='Zwickyverse',
                                     cutouts=classifications, classes=list(classes.values()))
    elif flask.request.method == 'POST':
        classifications = json.loads(flask.request.get_data())
        classifications = {k: v for k, v in classifications.items() if len(v) > 0}
        date = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        with open(f'/Users/dmitryduev/_caltech/python/deep-asteroids/data-raw/zooniverse.{date}.json', 'w') as f:
            json.dump(classifications, f, indent=2)
        return flask.jsonify({'status': 'success'})




@app.route('/projects', strict_slashes=False, methods=['GET'])
@app.route('/projects/<string:project_id>', methods=['GET'])
@flask_login.login_required
def test(project_id=None):
    return str(project_id)


@app.route('/projects', methods=['PUT'])
@flask_login.login_required
def add_project():
    """
        Add new project to DB
    :return:
    """
    try:
        user_id = flask_login.current_user.id

        # print(flask.request.json)
        name = flask.request.json.get('name', None)
        description = flask.request.json.get('description', '')
        classes = flask.request.json.get('classes', '')

        if len(name) == 0 or len(classes) == 0:
            return 'name and classes must be set'

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

        return 'success'

    except Exception as _e:
        print(_e)
        return str(_e)


@app.route('/projects', methods=['DELETE'])
@flask_login.login_required
def remove_project():
    """
        Remove project from DB
    :return:
    """
    try:
        user_id = flask_login.current_user.id

        # get project_id from request
        project_id = flask.request.json.get('project_id', None)
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
                        mongo.db.datasets.delete_many({'project_id': ObjectId(project_id)})

                        # clean up users:
                        mongo.db.users.update(
                            {f'permissions.{project_id}': {'$exists': True}},
                            {'$unset': {
                                f'permissions.{project_id}': ''
                            }},
                            multi=True
                        )

                        return 'success'
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
        print(_e)
        return str(_e)


@app.route('/projects', methods=['POST'])
@flask_login.login_required
def edit_project():
    """
        Edit project to DB
    :return:
    """
    try:
        user_id = flask_login.current_user.id

        # get project_id from request
        project_id = flask.request.json.get('project_id', None)
        if project_id is not None:

            _tmp = mongo.db.projects.find_one({'_id': ObjectId(project_id)})
            # print(_tmp)

            if _tmp is not None and len(_tmp) > 0:

                # check user is admin for the project:
                permissions = mongo.db.users.find_one({'_id': user_id}, {'_id': 0, 'permissions': 1})['permissions']
                if project_id in permissions:
                    if permissions[project_id]['role'] == 'admin':

                        print(flask.request.json)
                        add_user = flask.request.json.get('add_user', None)
                        add_user_role = flask.request.json.get('add_user_role', None)
                        add_classes = flask.request.json.get('classes', None)
                        # TODO:
                        remove_user = flask.request.json.get('remove_user', None)
                        remove_class = flask.request.json.get('remove_class', None)

                        # adding class(es)?
                        if add_classes is not None:

                            if len(add_classes) == 0:
                                return 'classes must be set'

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
                                return f'role {add_user_role} not recognized'
                            _tmp = mongo.db.users.find_one({'_id': add_user}, {'_id': 1})
                            if _tmp is not None and len(_tmp) > 0:
                                mongo.db.users.update_one(
                                    {'_id': add_user},
                                    {'$set': {
                                        f'permissions.{project_id}': {'role': add_user_role,
                                                                      'classifications': {}}
                                    }}
                                )
                            else:
                                return f'user {add_user} not found'

                        return 'success'
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
        print(_e)
        return str(_e)


if __name__ == '__main__':
    app.run(host=config['server']['host'], port=config['server']['port'], threaded=True)
