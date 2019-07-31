# -*- coding: utf-8 -*-
# USER: Test
# Time: 2019/7/31 17:18

import inspect
import functools

global_map = {

}


def register(name):
    """
    注册服务
    :param name: 服务类型名称，rpc, cmd
    :return:
    """
    def _wrapper(func):
        arg_spec = inspect.getfullargspec(func)
        global_map[func.__name__] = (func, arg_spec.args, arg_spec.defaults)
        @functools.wraps(func)
        def __wrapper(*args, **kwargs):
            print(name, 'call %s():' % func.__name__, args, kwargs)
            try:
                return func(*args, **kwargs)
            except Exception as e:
                print("e: ", e)

        return __wrapper
    print("1 ", name)
    return _wrapper


@register('rpc')
def test(a, b, c=1, d=3, e=None):
    print(a, b, c, d)
    return a * b * c * d


@register('rpc')
def test1(a, b, c=2, d=5, g=None):
    print(a, b, c, d)
    return a * b * c * d


if __name__ == '__main__':
    print(global_map)
    print(test(1))
