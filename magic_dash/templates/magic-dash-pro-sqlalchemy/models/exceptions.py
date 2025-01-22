class InvalidUserError(Exception):
    """非法用户信息"""

    pass


class ExistingUserError(Exception):
    """用户信息已存在"""

    pass
