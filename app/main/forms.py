from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField,\
    SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp
from wtforms import ValidationError
from ..models import Role, User
from flask_pagedown.fields import PageDownField


class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EditProfileForm(FlaskForm):  # 用户级编辑资资料表单
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('提交')
# 管理员修改用户email的时候，填写的不能是其它用户的Email， 因此Email验证函数需要知道被修改的用户，
# 因此我们创建表单实例的时候需要把user传进构造函数并保存下来


class EditProfileAdminForm(FlaskForm):  # 管理员使用的编辑资料的表单

    email = StringField('Email', validators=[DataRequired(), Length(1, 64),

                                             Email()])

    username = StringField('Username', validators=[

        DataRequired(), Length(1, 64),

        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,

               'Usernames must have only letters, numbers, dots or '

               'underscores')])

    confirmed = BooleanField('Confirmed')

    role = SelectField('Role', coerce=int)  # SelectField实例必须在其choices属性中设置各个选项
    # 选项必须是一个由元组组成的列表，各元组都包含两个元素，以及显式在控件中的文本字符串。choices列表在表单的构造函数中设定
    # 其值从Role模型中获取，使用一个查询按照角色名的字母顺序排列所有的角色。元组中的标识符是角色的ID，因为这是个郑虎，所以在SelectField
    # 因为角色id是个整数，所以把字段值转化为整数而不是字符串，构造函数中加上coerce=int 参数，把字段的值转化为整数
    name = StringField('Real name', validators=[Length(0, 64)])

    location = StringField('Location', validators=[Length(0, 64)])

    about_me = TextAreaField('About me')

    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):  # 表单构造函数接收用户对象作为参数，

        # 并将其保存在成员变量中，供后面的自定义的验证方法使用

        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        # 选项由元祖组成，选项的标识符和显示空间中的文本字符串
        self.role.choices = [(role.id, role.name)  # 选项标识符和显示在控件里的文本字符串组构成的元组

                             for role in Role.query.order_by(Role.name).all()]  # 通过未绑定方法来调用父类的构造方法 Role.name

        self.user = user

    def validate_email(self, field):
        # 首先检查字段是否发生了变化，并保证新值不和其他用户的字段值重复
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():

            raise ValidationError('邮箱已注册')

    def validate_username(self, field):
        # 首先检查字段是否发生了变化，并保证新值不和其他用户的字段值重复
        # 检查提交的昵称
        # 如果字段值没有变，跳过验证
        # 如果新的与旧的不同，但与其他用户的昵称冲突，报错
        # 如果有变化，且与其他用户不冲突，验证通过
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class PostForm(FlaskForm):
    body = PageDownField("想啥呢?", validators=[DataRequired()])
    submit = SubmitField('提交')


class CommentForm(FlaskForm):  # 评论输入表单
    body = StringField('添加你的评论', validators=[DataRequired()])
    submit = SubmitField('提交')