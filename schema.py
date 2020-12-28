from api import ma
from . import db
from api.models import *
from marshmallow import Schema, fields


class UserSchema(Schema):
    id = fields.Int()
    public_id = fields.Str()
    email = fields.Email()
    password_hash = fields.Str()
    token = fields.Str()
    first_name = fields.Str()
    last_name = fields.Str()


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class OrganizationSchema(Schema):
    id = fields.Int()
    public_id = fields.Str()
    name = fields.Str()
    users = fields.Method('users_list')
    projects = fields.Method('projects_list')

    def users_list(self, organization):
        users = organization.users_list()
        users_json = senstive_users_schema.dump(users)
        return users_json

    def projects_list(self, organization):
        projects = organization.project_list()
        projects_json = projects_schema.dump(projects)
        return projects_json


org_schema = OrganizationSchema()
orgs_schema = OrganizationSchema(many=True)


class ProjectSchema(Schema):
    id = fields.Int()
    public_id = fields.Str()
    name = fields.Str()
    description = fields.Str()
    deadline = fields.DateTime()
    created_on = fields.DateTime()
    last_updated = fields.DateTime()
    numberOfUsers = fields.Method("number_of_users")
    tasks = fields.Method("get_tasks")

    def number_of_users(self, project):
        return project.number_of_users()

    def get_tasks(self, project):
        tasks = project.tasks()
        json_tasks = tasks_schema.dump(tasks)
        return json_tasks


project_schema = ProjectSchema()
projects_schema = ProjectSchema(many=True)


class TaskSchema(Schema):

    id = fields.Int()
    public_id = fields.Str()
    name = fields.Str()
    description = fields.Str()
    eta = fields.DateTime()
    deadline = fields.DateTime()
    createdOn = fields.DateTime()
    lastUpdated = fields.DateTime()
    status = fields.Str()
    difficulty = fields.Int()
    projectId = fields.Int()
    projectName = fields.Method("project_name")

    def project_name(self, task):
        parent_project = Project.query.filter_by(id=task.project_id).first()
        proj_name = parent_project.name
        return proj_name


task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)


class SensitiveUserSchema(Schema):
    public_id = fields.Str()
    email = fields.Email()
    firstName = fields.Str()
    lastName = fields.Str()


sensitive_user_schema = SensitiveUserSchema()
senstive_users_schema = SensitiveUserSchema(many=True)
