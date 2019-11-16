from functools import wraps

from flask import g

from .errors import forbidden
#  permission_required装饰器
def permission_required(permission):
# 通过形参实现了一个装饰器类。对于不同针对性的装饰器，都可以调用这个函数的实现，而只需要做最小的改动（传递形参）
    def decorator(f):
# 使用functools模块提供的@wraps装饰器可以避免避免被装饰函数的特殊属性被更改，比如函数名称__name__被更改
#  如果不使用这个模块，则会导致函数名被替换从而导致端点（端点的默认值是函数名）出错
        @wraps(f)
        def decorated_function(*args, **kwargs):
            #  *args表示任何多个无名参数，它是一个tuple
            #  **kwargs表示关键字参数，它是一个dict
            # 这个装饰器方法把原函数的形参继承了。因此实际上相当于在原函数开头增加了这个函数的内容
            if not g.current_user.can(permission):
                #  current_user是从内存中取（服务端），然后permission就会根据我们
                #  实际需要验证的permission进行形参到实参的转化
                return forbidden('Insufficient permissions')

            return f(*args, **kwargs)
            #  结束判断，把参数传递给原函数（此处的f()即是原函数（更具体的权限验证装饰器），只是f是个丑陋的形参而已）
        return decorated_function

    return decorator