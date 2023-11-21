from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.contrib.fastapi import register_tortoise
from tortoise.models import Model
from tortoise import fields
from passlib.hash import bcrypt


app = FastAPI()

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique = True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)

User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly = True) 

@app.post('/user', response_model=User_Pydantic)
async def create_user(form_data: UserIn_Pydantic):
    user = User(username = form_data.username, password_hash = bcrypt.hash(form_data.password_hash))
    await user.save()
    return await User_Pydantic.from_tortoise_orm(user)

register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models':['main']},
    generate_schemas=True,
    add_exception_handlers=True
)
