
from flask import g, jsonify

from flask_httpauth import HTTPBasicAuth

from ..models import User

from . import api

from .errors import unauthorized, forbidden


auth = HTTPBasicAuth()

# 认证的回调函数
@auth.verify_password
def verify_password(email_or_token, password):

    if email_or_token == '':

        return False

    if password == '':

        g.current_user = User.verify_auth_token(email_or_token)

        g.token_used = True

        return g.current_user is not None

    user = User.query.filter_by(email=email_or_token.lower()).first()

    if not user:

        return False
    #  回调函数将通过身份验证的用户保存在Flaskd的上下文变量g中，供视图函数稍后使用
    g.current_user = user

    g.token_used = False

    return user.verify_password(password)


@auth.error_handler
def auth_error():

    return unauthorized('Invalid credentials')

# 使用一次login_required装饰器，将其应用到整个蓝本上去；
@api.before_request
@auth.login_required
def before_request():

    if not g.current_user.is_anonymous and not g.current_user.confirmed:

        return forbidden('Unconfirmed account')


@api.route('/tokens/', methods=['POST'])
def get_token():

    if g.current_user.is_anonymous or g.token_used:

        return unauthorized('Invalid credentials')

    return jsonify({'token': g.current_user.generate_auth_token(

        expiration=3600), 'expiration': 3600})

