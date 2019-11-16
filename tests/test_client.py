import re

import unittest

from app import create_app, db

from app.models import User, Role

class FlaskClientTestCase(unittest.TestCase):
    # 该方法会首先执行，方法名为固定写法，该方法会首先执行，相当于做测试前的准备工作
    def setUp(self):

        self.app = create_app('testing')

        self.app_context = self.app.app_context()

        self.app_context.push()

        db.create_all()

        Role.insert_roles()

        self.client = self.app.test_client(use_cookies=True)

    # 该方法会在测试代码执行完后执行，方法名为固定写法， 该方法会在测试代码执行完后执行，相当于做测试后的扫尾工作
    def tearDown(self):

        db.session.remove()

        db.drop_all()

        self.app_context.pop()

    def test_home_page(self):

        response = self.client.get('/')

        self.assertEqual(response.status_code, 200)

        self.assertTrue(b'Stranger' in response.data)

    def test_register_and_login(self):

        # 注册新用户

        response = self.client.post('/auth/register', data={

            'email': 'john@example.com',

            'username': 'john',

            'password': 'cat',

            'password2': 'cat'

        })

        self.assertEqual(response.status_code, 302)
        # 使用新注册的账户登录

        response = self.client.post('/auth/login', data={

            'email': 'john@example.com',

            'password': 'cat'

        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)

        self.assertTrue(re.search(b'Hello,\s+john!', response.data))

        self.assertTrue(

            b'You have not confirmed your account yet' in response.data)



            #  发送确认令牌

        user = User.query.filter_by(email='john@example.com').first()

        token = user.generate_confirmation_token()

        response = self.client.get('/auth/confirm/{}'.format(token),

                                   follow_redirects=True)

        user.confirm(token)

        self.assertEqual(response.status_code, 200)

        self.assertTrue(

            b'You have confirmed your account' in response.data)



        # 退出

        response = self.client.get('/auth/logout', follow_redirects=True)

        self.assertEqual(response.status_code, 200)

        self.assertTrue(b'You have been logged out' in response.data)