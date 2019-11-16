from datetime import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request
from flask_login import UserMixin, AnonymousUserMixin
from . import db, login_manager
from markdown import markdown
import bleach
from app.exceptions import ValidationError


class Permission:

    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)  # 只能有一个角色的这个字段可以设置为true，其他都为false
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):   # 重写父类Role的构造方法
        super(Role, self).__init__(**kwargs)  # 通过父类的super()函数来调用父类的构造方法，也可通过未绑定方法来调用父类的构造方法
        if self.permissions is None:  # 例如Role.__init__(self,**kwargs)
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT,
                              Permission.WRITE, Permission.MODERATE,
                              Permission.ADMIN],
        }

        default_role = 'User'  # 默认角色是用户

        for r in roles:
            role = Role.query.filter_by(name=r).first()   # 搜索三种角色，在数据库表的存在
            if role is None:   # 如果数据库不存在这种角色名时，马上添加进去，方便以后拓展
                role = Role(name=r)
            role.reset_permissions()  # 重置权限
            for perm in roles[r]:  # 权限重新一个个加进去
                role.add_permission(perm)
            role.default = (role.name == default_role)  # 将默认用户写进数据库
            db.session.add(role)
        db.session.commit()

    def add_permission(self, perm):  # Role 模型管理权限的方法，添加权限
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):  # 移除权限
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):  # 判断是否含有权限
        return self.permissions & perm == perm  # 检查组合权限是否包含指定的单独权限

    def __repr__(self):
        return '<Role %r>' % self.name


class Follow(db.Model):  # 关注关系中关联表的模型实现

    __tablename__ = 'follows'

    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),

                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):  #
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))  # 在User模型中创建的role_id字段为存储Role记录主键值的外键字段
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)  # 默认属性是False，也就是未认证
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    # 增加confirmed属性，默认为False，意思为未确认的账户
    #  confirm()方法检验令牌，如果令牌验证通过，就把confirmed 属性设置为true,具体操作转到蓝本auth 的视图函数
    avatar_hash = db.Column(db.String(32))
    # 添加到User模型中的posts属性代表这个关系的面向对象视角，对于一个User实例
    # 其posts 属性将返回与user关联的posts组成的列表（即多那一端）
    # db.relationship()第一个参数表明这个关系的另一端是哪个模型
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    #  User和Post建立了联系，并在posts中创建了author属性，只不过author属性不直接显示，而是通过author_id来进行体现。
    # 关注我的
    followed = db.relationship('Follow',

                               foreign_keys=[Follow.follower_id],
                               #  为消除外键间的歧义，定义关系时必须使用可选参数foreign_keys指定外键
                               backref=db.backref('follower', lazy='joined'),
                               #  第一个lazy，即lazy = joined，表示直接通过连接查询来加载对象，
                               #  即通过一条语句查出用户和所有的followed过的用户（假设followed字段）
                               #  而假设把它设为select的话，则需要对每个followed的用户进行一次查询操作
                               lazy='dynamic',
                               #  第二个lazy，即lazy=dynamic，表示此操作返回的是一个查询对象，而不是结果对象，
                               #  可以简单理解为一个半成品的sql语句，可以在其上添加查询条件，返回使用条件之后的结果
                               cascade='all, delete-orphan')
#  这两个lazy的作用都在一对多关系中的一的一侧设定，即第一个在回引，即直接可以通过已关注的对象找到自己，
#  第二个是在本身，即可以直接返回的已关注列表，并可进行筛选操作（followed字段）
    # 我关注的
    followers = db.relationship('Follow',

                                foreign_keys=[Follow.followed_id],

                                backref=db.backref('followed', lazy='joined'),

                                lazy='dynamic',

                                cascade='all, delete-orphan')
#  cascade表示主表字段发生变化的时候，外键关联表的响应规则，all表示假设新增用户后，
#  自动更新所有的关系对象，all也为默认值，但在这个关系中，删除用户后显然不能删除所有与他关联的用户，
#  包括他关注的和关注他的，所以使用delete-orphan的删除选项，即只删除关联关系的对象，对于这个例子来说，也就是所有Follow对象
#  把用户转化为JSON格式的序列化字典
    def to_json(self):
        json_user = {
            'url': url_for('api.get_user', id=self.id),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts_url': url_for('api.get_user_posts', id=self.id),
            'followed_posts_url': url_for('api.get_user_followed_posts',
                                          id=self.id),
            'post_count': self.posts.count()
        }
        return json_user
#  生成基于令牌的身份验证
    def generate_auth_token(self, expiration):

        s = Serializer(current_app.config['SECRET_KEY'],

                       expires_in=expiration)

        return s.dumps({'id': self.id}).decode('utf-8')
#  verify_auth_token（）方法接受的参数是一个令牌，如果令牌有效就返回对应的客户
    @staticmethod
    def verify_auth_token(token):

        s = Serializer(current_app.config['SECRET_KEY'])

        try:

            data = s.loads(token)

        except:

            return None

        return User.query.get(data['id'])

    @staticmethod  # 把用户设置为自己的关注者
    def add_self_follows():

        for user in User.query.all():

            if not user.is_following(user):

                user.follow(user)

                db.session.add(user)

                db.session.commit()

    def __init__(self, **kwargs):   # 重写父类Role的构造方法
        super(User, self).__init__(**kwargs)  # 通过父类的super()函数来调用父类的构造方法，也可通过未绑定方法来调用父类的构造方法
        # 分配管理员角色:
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name="ADMIN").first()
        # 如果一个用户的角色不存在
            if self.role is None:
                # 分配一个默认角色
                self.role = Role.query.filter_by(default=True).first()

        if self.email is not None and self.avatar_hash is None:  # 模型初始化时，散列值存储在新增的avatar_hash()属性中
            self.avatar_hash = self.gravatar_hash()
        self.follow(self)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        # 以SECRET_KEY作为参数 ，TimedJSONWebSignatureSerializer类生成具有过期时间的JSON Web签名
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        # dumps()方法为指定的数据生成一个加密签名，然后进行序列化生成令牌字符串
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # try解析加密签名，如果不能返回False
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        # 如果加密签名中的‘confirm’的值不等于用户id，返回False
        if data.get('confirm') != self.id:
            return False
        # 等于的话，用户的confirmed属性改为True，意思为确认过的账户
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    comments = db.relationship('Comment', backref='author', lazy='dynamic')
#  # 静态方法无需实例化，即User.reset_password
    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps(
            {'change_email': self.id, 'new_email': new_email}).decode('utf-8')

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = self.gravatar_hash()  # 如果客户更新了邮箱，则重新计算MD5散列值
        db.session.add(self)
        return True

    def gravatar_hash(self):

        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self, size=100, default='identicon', rating='g'):

        url = 'https://secure.gravatar.com/avatar'

        hash = self.avatar_hash or self.gravatar_hash()

        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(

            url=url, hash=hash, size=size, default=default, rating=rating)

# 为了简化角色和权限的实现过程，可以在User 模型中添加一个辅助方法，检查赋予用户的角色是否有某种权限

    def can(self, perm):  # 如果角色中包含请求的权限，那么模型中添加的can()方法会返回True，表示允许用户执行此项操作

        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):  # 因为经常需要检查是否有管理权限，所以还单独实现了is_administrator方法

        return self.can(Permission.ADMIN)

    def ping(self):  # 为了确保每个用户最后的访问时间都是最新的，每次收到用户的请求时都要调用ping()方法

        self.last_seen = datetime.utcnow()

        db.session.add(self)

    # 关注用户
    def follow(self, user):

        if not self.is_following(user):

            f = Follow(followed=user)
            # 把关注者和被关注者联结在一起传入构造器并添加到数据库中
            self.followed.append(f)

    # 取消关注
    def unfollow(self, user):
        # followed找到联结用户和被关注用户的实例
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            # 销毁用户之间的联结，删除这个对象即可
            self.followed.remove(f)

    # 我是否关注此用户
    def is_following(self, user):

        if user.id is None:  # 防止用户已注册未提交到数据库

            return False

        return self.followed.filter_by(followed_id=user.id).first() is not None

    # 此用户是否关注了我
    def is_followed_by(self, user):

        if user.id is None:

            return False

        return self.followers.filter_by(follower_id=user.id).first() is not None

    # 定义方法为属性，找到关注用户所发表的文章，SQLalchemy 首先收集所有的过滤器，再以最高效的方式生成查询
    @property
    def followed_posts(self):

        return db.session.query(Post).select_from(Follow).\
            filter(Follow.follower_id == self.id).join(Post, Follow.followed_id == Post.author_id)
    #  db.session.query(Post)指明这个查询将返回Post对象
    #  select_from(Follow)的意思是这个查询从Follow模型开始
    #  filter(Follow.follower_id == self.id)使用关注用户过滤的follows表
    #  join(Post, Follow.followed_id == Post.author_id)联结filter_by得到的结果和Post对象

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):

    def can(self, permissions):

        return False

    def is_administrator(self):

        return False


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 建立post模型
class Post(db.Model):

    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)

    body = db.Column(db.Text)

    body_html = db.Column(db.Text)

    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    #  Post类中创建一个方法，来实现markdown原文本 → html代码的一个转换。
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        # allowed_tags代表允许使用的html标签。
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        # allowed_attribute = ['src', 'title', 'alt', 'href', 'class']
        # allowed_attribute代表允许使用的属性和链接
        target.body_html = bleach.linkify(bleach.clean(
            # 第一个clean是使用bleach函数的队转化的# HTML 文本进行清理（markdown）
            markdown(value, output_format='html',),

            tags=allowed_tags,  strip=True))
        # extensions=['markdown.extensions.fenced_ code','markdown.extensions.codehilite']),

#  markdown(value,output_format='html')value是指markdown源文本,output_format指转化为html代码。
#  bleach.clean是一个内容清扫工具,将源文本中的一些错误语法清除。　
#  clean（） 函数 还 支持 一个 strip 参数， 如果 设为 True， 那么会直接删除白名单之外的标签。 默认为 False。
#  linkify则负责将相应的url转化为链接。linkify()函数会自动识别并转 文本中包含的URL， 返回 处理 后的 文本。
#  将文章转化为JSON格式的序列化字典
    def to_json(self):

        json_post = {

            'url': url_for('api.get_post', id=self.id),

            'body': self.body,

            'body_html': self.body_html,

            'timestamp': self.timestamp,

            'author_url': url_for('api.get_user', id=self.author_id),

            'comments_url': url_for('api.get_post_comments', id=self.id),

            'comment_count': self.comments.count()

        }

        return json_post
#   从JSON格式数据创建一篇博客文章
    @staticmethod
    def from_json(json_post):

        body = json_post.get('body')

        if body is None or body == '':

            raise ValidationError('post does not have a body')

        return Post(body=body)


db.event.listen(Post.body, 'set', Post.on_changed_body)
# set代表只要这个类的实例的body属性有了新值，就调用on_changed_body函数


class Comment(db.Model):  # 评论模型

    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)

    body = db.Column(db.Text)

    body_html = db.Column(db.Text)

    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    #  查禁不当言论
    disabled = db.Column(db.Boolean)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):

        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',

                        'strong']

        target.body_html = bleach.linkify(bleach.clean(

            markdown(value, output_format='html'),

            tags=allowed_tags, strip=True))


db.event.listen(Comment.body, 'set', Comment.on_changed_body)