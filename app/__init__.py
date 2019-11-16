from config import config
from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_moment import Moment
from flask_pagedown import PageDown
from flask_sqlalchemy import SQLAlcheml

#  扩展类
bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()
migrate = Migrate()

login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # LoginManger 对象的login_view属性用于设置登陆页面的端点，
# 匿名用户尝试访问受保护的页面时，Flask-Login将重定向到登陆页面 因为登录页面由蓝本中定义，因此要在前面加上蓝本名字


def create_app(config_name):
    app = Flask(__name__, template_folder='C:/Users/jieji/.virtualenvs/jieji-8rKxeQws/flasky/app/templates')
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    pagedown.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    # 注册API文本
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api/v1')
    # 此蓝本所有路由的url都将以/api/v1开头
    return app


