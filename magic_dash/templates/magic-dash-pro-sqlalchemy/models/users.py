from typing import Dict, List, Union

from configs import AuthConfig
from sqlalchemy import Column, String
from sqlalchemy.types import JSON
from werkzeug.security import check_password_hash

from . import Base, db
from .exceptions import ExistingUserError, InvalidUserError


class Users(Base):
    """用户信息表模型类"""
    __tablename__ = 'users'

    # 用户id，主键
    user_id = Column(String, primary_key=True)

    # 用户名，唯一
    user_name = Column(String, unique=True, nullable=False)

    # 用户密码散列值
    password_hash = Column(String, nullable=False)

    # 用户角色，全部可选项见configs.AuthConfig.roles
    user_role = Column(String, default=AuthConfig.normal_role)

    # 用户最近一次登录会话token
    session_token = Column(String, nullable=True)

    # 用户其他辅助信息，任意JSON格式，允许空值
    other_info = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<User {self.user_name}>"

    @classmethod
    def get_user(cls, user_id: str):
        """根据用户id查询用户信息"""
        user = cls.query.get(user_id)
        return user if user else None

    @classmethod
    def get_user_by_name(cls, user_name: str):
        """根据用户名查询用户信息"""
        user = cls.query.filter_by(user_name=user_name).first()
        return user if user else None

    @classmethod
    def get_all_users(cls):
        """获取所有用户信息"""
        users = cls.query.all()
        return [
            {
                'user_id': user.user_id,
                'user_name': user.user_name,
                'user_role': user.user_role,
                'session_token': user.session_token,
                'other_info': user.other_info
            }
            for user in users
        ]

    @classmethod
    def check_user_password(cls, user_id: str, password: str):
        """校验用户密码"""
        user = cls.get_user(user_id)
        if user:
            return check_password_hash(user.password_hash, password)
        return False

    @classmethod
    def add_user(
        cls,
        user_id: str,
        user_name: str,
        password_hash: str,
        user_role: str = "normal",
        other_info: Union[Dict, List] = None,
    ):
        """添加用户"""
        # 若必要用户信息不完整
        if not (user_id and user_name and password_hash):
            raise InvalidUserError("用户信息不完整")

        # 若用户id已存在
        elif cls.get_user(user_id):
            raise ExistingUserError("用户id已存在")

        # 若用户名存在重复
        elif cls.get_user_by_name(user_name):
            raise ExistingUserError("用户名已存在")

        # 执行用户添加操作
        try:
            new_user = cls(
                user_id=user_id,
                user_name=user_name,
                password_hash=password_hash,
                user_role=user_role,
                other_info=other_info,
            )
            db.add(new_user)
            db.commit()
        except:
            db.rollback()
            raise

    @classmethod
    def delete_user(cls, user_id: str):
        """删除用户"""
        try:
            user = cls.get_user(user_id)
            if user:
                db.delete(user)
                db.commit()
        except:
            db.rollback()
            raise

    @classmethod
    def update_user(cls, user_id: str, **kwargs):
        """更新用户信息"""
        try:
            user = cls.get_user(user_id)
            if user:
                for key, value in kwargs.items():
                    setattr(user, key, value)
                db.commit()
                return user
        except:
            db.rollback()
            raise
        return None
