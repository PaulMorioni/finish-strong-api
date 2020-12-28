from flask import Blueprint, jsonify, request, make_response, session
from . import db
from .models import *
from .mock_data import generate_data
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import json
from flask_restful import Resource, Api
from flask_marshmallow import Marshmallow
from .schema import *
import jwt
import os

main = Blueprint('main', __name__)
api = Api(main)
SECRET_KEY = os.environ.get("SECRET_KEY")


def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return make_response(jsonify({'message': 'Token is missing!'}), 401)

        try:
            data = jwt.decode(token, SECRET_KEY)
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return make_response(jsonify({'message': 'Token is invalid!'}), 401)

        return f(current_user, *args, **kwargs)

    return wrapper


class UserResource(Resource):
    def get(self, user_id):
        try:
            user = User.query.filter_by(public_id=user_id).first()
        except:
            return 'User Not Found', 404
        s_user = SensitiveUser(
            user.public_id, user.email, user.first_name, user.last_name)
        user_json = sensitive_user_schema.dump(s_user)
        return {'user': user_json}, 200

    def put(self, user_id):
        try:
            user = User.query.filter_by(public_id=user_id).first()
        except:
            return 'Record Not Found', 404

        new_user_data = request.get_json()

        if 'email' in new_user_data:
            user.email = new_user_data['email']
        if 'first_name' in new_user_data:
            user.first_name = new_user_data['first_name']
        if 'last_name' in new_user_data:
            user.last_name = new_user_data['last_name']

        return 'Record Updated', 200

    def delete(self, user_id):
        try:
            user = User.query.filter_by(public_id=user_id).first()
        except:
            return 'Record Not Found', 404
        db.session.delete(user)
        db.session.commit()
        return 'Record Deleted', 200


class UsersResource(Resource):
    def get(self):
        try:
            users = User.query.all()
            users_json = users_schema.dump(users)
            return users_json, 200
        except:
            return 'Record Not Found', 404

    def post(self):
        user_data = request.get_json()
        user_check = User.query.filter_by(email=user_data['email']).first()
        if user_check:
            return 'Email Already In Use', 400
        else:
            password_hash = generate_password_hash(user_data['password'])
            try:
                print(user_data)
                new_user = User(email=user_data['email'], password_hash=password_hash,
                                first_name=user_data['firstName'], last_name=user_data['lastName'])

                db.session.add(new_user)
                db.session.commit()
                return 'User Created', 201
            except:
                return 'Invalid Entry', 400


class OrganizationResource(Resource):
    method_decorators = [token_required]

    def get(self, current_user, org_id):
        try:
            org = Organization.query.filter_by(public_id=org_id).first()

            if org in current_user.organization:
                org_json = org_schema.dump(org)
                return org_json
            else:
                return 'Not Authorized', 401
        except:
            return 'Record Not Found', 404

    def put(self, current_user, org_id):
        try:
            org = Organization.query.filter_by(public_id=org_id).first()
        except:
            return 'Record Not Found', 404
        if org in current_user.organization:

            new_org_data = request.get_json()
            if 'name' in new_org_data:
                org.name = new_org_data['name']
            return 'Record Updated', 201
        else:
            return 'Not Authorized', 401

    def delete(self, current_user, org_id):
        try:
            org = Organization.query.filter_by(public_id=org_id).first()
        except:
            return 'Record Not Found', 404
        if org in current_user.organization:
            db.session.delete(org)
            db.session.commit()
            return 'Record Deleted', 200
        else:
            return 'Not Authorized', 401


class OrganizationsResource(Resource):
    method_decorators = [token_required]

    def get(self, current_user):
        try:
            orgs = current_user.organization
            orgs_json = orgs_schema.dump(orgs)
            return {'organizations': orgs_json}, 200
        except:
            return 'Record Not Found', 404

    def post(self, current_user):
        try:
            org_data = request.get_json()
            new_org = Organization(name=org_data['name'])
            db.session.add(new_org)
            current_user.assign_org(new_org)
            db.session.commit()
            return 'Record Created', 201
        except:
            return 'Invalid Entry', 400


class ProjectResource(Resource):
    method_decorators = [token_required]

    def get(self, current_user, project_id):
        try:
            project = Project.query.filter_by(public_id=project_id).first()
        except:
            return 'Record Not Found', 404
        if project in current_user.project:
            proj_json = project_schema.dump(project)
            return proj_json, 200
        else:
            return 'Not Authorized', 401

    def put(self, current_user, project_id):
        try:
            project = Project.query.filter_by(public_id=project_id).first()
            new_project_data = request.get_json()

            if project in current_user.project:
                if 'name' in new_project_data:
                    project.name = new_project_data['name']
                if 'description' in new_project_data:
                    project.description = new_project_data['description']
                if 'deadline' in new_project_data:
                    project.deadline = new_project_data['deadline']
                if 'organization_id' in new_project_data:
                    project.organization_id = new_project_data['organization_id']

                project.update_project()
                db.session.commit()
                return 'Record Updated', 200
            else:
                return 'Not Authorized', 401
        except:
            return 'Record Not Found', 404

    def delete(self, current_user, project_id):
        try:
            project = Project.query.filter_by(public_id=project_id).first()
            if project in current_user.project:
                db.session.delete(project)
                db.session.commit()
                return 'Record Deleted', 200
            else:
                return 'Not Authorized', 401
        except:
            return 'Record Not Found', 404


class ProjectsResource(Resource):
    method_decorators = [token_required]

    def get(self, current_user):
        try:
            projects = current_user.project
            projs_json = projects_schema.dump(projects)
            return {"projects": projs_json}, 200
        except:
            return 'Record Not Found', 404

    def post(self, current_user):
        project_data = request.get_json()
        try:
            new_project = Project(name=project_data['name'], description=project_data['description'],
                                  deadline=project_data['deadline'])
        except:
            return "Invalid Project Entry", 400

        organization_public_id = project_data['organization']
        try:
            organization = Organization.query.filter_by(
                public_id=organization_public_id).first()
        except:
            return "Organization Not Found", 40

        db.session.add(new_project)

        new_project.assign_org(organization)
        current_user.assign_project(new_project)
        db.session.commit()

        return 'Record Created', 201


class TaskResource(Resource):
    method_decorators = [token_required]

    def get(self, current_user, task_id):
        try:
            task = Task.query.filter_by(public_id=task_id).first()
        except:
            return 'Record Not Found', 404
        if task in current_user.task:
            task_json = task_schema.dump(task)
            return task_json, 200
        else:
            return 'Not Authorized', 401

    def put(self, current_user, task_id):
        try:
            task = Task.query.filter_by(public_id=task_id).first()
        except:
            return 'Record Not Found', 404

        if task in current_user.task:

            new_task_data = request.json
            if 'description' in new_task_data:
                task.description = str(new_task_data['description'])
            if 'eta' in new_task_data:
                task.eta = new_task_data['eta']
            if 'deadline' in new_task_data:
                task.deadline = new_task_data['deadline']
            if 'status' in new_task_data:
                task.status = str(new_task_data["status"])
            if 'difficulty' in new_task_data:
                task.difficulty = new_task_data['difficulty']
            if 'project_id' in new_task_data:
                task.project_id = new_task_data['project_id']

            task.update_task()
            db.session.commit()

            return 'Record Updated', 200
        else:
            return 'Not Authorized', 401

    def delete(self, current_user, task_id):
        try:
            task = Task.query.filter_by(public_id=task_id).first()
        except:
            return 'Record Not Found', 404

        if task in current_user.task:
            db.session.delete(task)
            db.session.commit()
            return 'Record Deleted', 200
        else:
            return 'Not Authorized', 401


class TasksResource(Resource):
    method_decorators = [token_required]

    def get(self, current_user):
        try:
            tasks = current_user.task
            tasks_json = tasks_schema.dump(tasks)
            return {'tasks': tasks_json}, 200
        except:
            return 'Record Not Found', 404

    def post(self, current_user):
        task_data = request.get_json()
        project_id = task_data['project_id']
        try:
            project = Project.query.filter_by(id=project_id).first()
        except:
            return 'Record Not Found', 404
        if project in current_user.project:
            new_task = Task(name=task_data['name'], description=task_data['description'],
                            eta=task_data['eta'], deadline=task_data['deadline'], difficulty=task_data['difficulty'], project_id=project.id)
            db.session.add(new_task)
            current_user.assign_task(new_task)
            db.session.commit()
            return 'Record Created', 201
        else:
            return 'Not Authorized', 401


@main.route('/api/login_user', methods={'POST'})
def login():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.utcnow(
        ) + timedelta(minutes=30)}, SECRET_KEY)

        return jsonify({'token': token.decode('UTF-8'), 'user_id': user.public_id}), 201

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


api.add_resource(UserResource, '/api/user/<user_id>')
api.add_resource(UsersResource, '/api/user')
api.add_resource(OrganizationResource, '/api/organization/<org_id>')
api.add_resource(OrganizationsResource, '/api/organization')
api.add_resource(ProjectResource, '/api/project/<project_id>')
api.add_resource(ProjectsResource, '/api/project')
api.add_resource(TaskResource, '/api/task/<task_id>')
api.add_resource(TasksResource, '/api/task')


@main.route('/api/generate_data', methods={'GET'})
def make_data():

    generate_data()
    return 'Done', 201


@main.errorhandler(404)
def not_found(e):
    return main.send_static_file('index.html')
