import uuid
import time
import dash
from dash import set_props, dcc
from flask_login import login_user
import feffery_antd_components as fac
from dash.dependencies import Input, Output, State
from flask_principal import identity_changed, Identity

from server import app, User
from models.users import Users


@app.callback(
    [Output("login-form", "helps"), Output("login-form", "validateStatuses")],
    [Input("login-button", "nClicks"), Input("login-password", "nSubmit")],
    [State("login-form", "values"), State("login-remember-me", "checked")],
    running=[
        [Output("login-button", "loading"), True, False],
    ],
    prevent_initial_call=True,
)
def handle_login(nClicks, nSubmit, values, remember_me):
    """处理用户登录逻辑"""

    time.sleep(0.25)

    values = values or {}

    # 若表单必要信息不完整
    if not (values.get("login-user-name") and values.get("login-password")):
        set_props(
            "global-message",
            {
                "children": fac.AntdMessage(
                    type="error",
                    content="请完善登录信息",
                )
            },
        )

        return [
            # 表单帮助信息
            {
                "用户名": "请输入用户名" if not values.get("login-user-name") else None,
                "密码": "请输入密码" if not values.get("login-password") else None,
            },
            # 表单帮助状态
            {
                "用户名": "error" if not values.get("login-user-name") else None,
                "密码": "error" if not values.get("login-password") else None,
            },
        ]

    # 校验用户登录信息

    # 根据用户名尝试查询用户
    match_user = Users.get_user_by_name(values["login-user-name"])

    # 若用户不存在
    if not match_user:
        set_props(
            "global-message",
            {
                "children": fac.AntdMessage(
                    type="error",
                    content="用户不存在",
                )
            },
        )

        return [
            # 表单帮助信息
            {"用户名": "用户不存在"},
            # 表单帮助状态
            {"用户名": "error"},
        ]

    else:
        # 校验密码

        # 若密码不正确
        if not Users.check_user_password(match_user.user_id, values["login-password"]):
            set_props(
                "global-message",
                {
                    "children": fac.AntdMessage(
                        type="error",
                        content="密码错误",
                    )
                },
            )

            return [
                # 表单帮助信息
                {"密码": "密码错误"},
                # 表单帮助状态
                {"密码": "error"},
            ]

        # 更新用户信息表session_token字段
        new_session_token = str(uuid.uuid4())
        Users.update_user(match_user.user_id, session_token=new_session_token)

        # 进行用户登录
        new_user = User(
            id=match_user.user_id,
            user_name=match_user.user_name,
            user_role=match_user.user_role,
            session_token=new_session_token,
        )

        # 会话登录状态切换
        login_user(new_user, remember=remember_me)

        # 在cookies更新ession_token字段
        dash.ctx.response.set_cookie("session_token", new_session_token)

        # 更新用户身份信息
        identity_changed.send(app.server, identity=Identity(new_user.id))

        # 重定向至首页
        set_props(
            "global-redirect",
            {"children": dcc.Location(pathname="/", id="global-redirect")},
        )

    return [{}, {}]
