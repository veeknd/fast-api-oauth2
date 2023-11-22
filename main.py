import jwt
from fastapi import FastAPI, Depends ,HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.contrib.fastapi import register_tortoise
from tortoise.models import Model
from tortoise import fields
from passlib.hash import bcrypt


app = FastAPI()
JWT_SECREKTKEY = 'secretkey'
class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique = True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)

User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly = True) 

OAuth2_scheme = OAuth2PasswordBearer('token')

async def get_current_user(token: str = Depends(OAuth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECREKTKEY, algorithms='HS256')
        user = await User.get(id = payload.get('id'))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ivalid username or password"
        )
    return user

async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

@app.post('/token')
async def get_token(form_data: OAuth2PasswordRequestForm=Depends()):
    user = await authenticate_user(username = form_data.username, password = form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password"
        )
    user_obj = await User_Pydantic.from_tortoise_orm(user)
    token = jwt.encode(user_obj.dict(), JWT_SECREKTKEY)
    return {'access_token':token, 'token_type':'bearer'}
    


@app.post('/user', response_model=User_Pydantic)
async def create_user(form_data: UserIn_Pydantic):
    user = User(username = form_data.username, password_hash = bcrypt.hash(form_data.password_hash))
    await user.save()
    return await User_Pydantic.from_tortoise_orm(user)

@app.get('/user/me',response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user

register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models':['main']},
    generate_schemas=True,
    add_exception_handlers=True
)
