from marshmallow import Schema, fields, post_load
from dataclasses import dataclass
from typing import List

@dataclass
class Project:
    project_id: str
    shorthand_name: str
    encrypted_salt: str

class ProjectSchema(Schema):
    project_id = fields.String(required=True)
    shorthand_name = fields.String(required=True)
    encrypted_salt = fields.String(required=True)
    @post_load
    def make_project(self, data, **kwargs):
        return Project(**data)

@dataclass
class SaltsRepo:
    storage_key_salt: str
    salts: List[Project]

class SaltsRepoSchema(Schema):
    storage_key_salt = fields.String(required=True)
    salts = fields.Nested(ProjectSchema,many=True, required=True)

    @post_load
    def make_salts_repo(self, data, **kwargs):
        return SaltsRepo(**data)