from dash import html, dcc
from flask_login import current_user
import feffery_antd_components as fac
import feffery_utils_components as fuc
from feffery_dash_utils.style_utils import style

from configs import BaseConfig, RouterConfig, LayoutConfig
from components import core_side_menu, personal_info, user_manage

# 令绑定的回调函数子模块生效
import callbacks.core_pages_c  # noqa: F401


def render():
    """渲染核心页面骨架"""

    return html.Div(
        [
            # 核心页面常量参数数据
            dcc.Store(
                id="core-page-config",
                data=dict(core_side_width=LayoutConfig.core_side_width),
            ),
            # 核心页面独立路由监听
            dcc.Location(id="core-url"),
            # ctrl+k快捷键监听
            fuc.FefferyKeyPress(id="core-ctrl-k-key-press", keys="ctrl.k"),
            # 注入个人信息模态框
            personal_info.render(),
            # 若当前用户角色为系统管理员
            *(
                # 注入用户管理抽屉
                [
                    user_manage.render(),
                ]
                if current_user.user_role == "admin"
                else []
            ),
            # 页首
            fac.AntdRow(
                [
                    # logo+标题+版本+侧边折叠按钮
                    fac.AntdCol(
                        fac.AntdFlex(
                            [
                                dcc.Link(
                                    fac.AntdSpace(
                                        [
                                            # logo
                                            html.Img(
                                                src="/assets/imgs/logo.svg",
                                                height=32,
                                                style=style(display="block"),
                                            ),
                                            fac.AntdSpace(
                                                [
                                                    # 标题
                                                    fac.AntdText(
                                                        BaseConfig.app_title,
                                                        strong=True,
                                                        style=style(fontSize=20),
                                                    ),
                                                    fac.AntdText(
                                                        BaseConfig.app_version,
                                                        className="global-help-text",
                                                        style=style(fontSize=12),
                                                    ),
                                                ],
                                                align="baseline",
                                                size=3,
                                                id="core-header-title",
                                            ),
                                        ]
                                    ),
                                    href="/",
                                ),
                                # 侧边折叠按钮
                                fac.AntdButton(
                                    fac.AntdIcon(
                                        id="core-side-menu-collapse-button-icon",
                                        icon="antd-menu-fold",
                                        className="global-help-text",
                                    ),
                                    id="core-side-menu-collapse-button",
                                    type="text",
                                    size="small",
                                ),
                            ],
                            id="core-header-side",
                            justify="space-between",
                            align="center",
                            style=style(
                                width=LayoutConfig.core_side_width,
                                height="100%",
                                paddingLeft=20,
                                paddingRight=20,
                                borderRight="1px solid #dae0ea",
                                boxSizing="border-box",
                            ),
                        ),
                        flex="none",
                    ),
                    # 页面搜索+功能图标+用户信息
                    fac.AntdCol(
                        fac.AntdFlex(
                            [
                                # 页面搜索
                                fac.AntdSpace(
                                    [
                                        fac.AntdSelect(
                                            id="core-page-search",
                                            placeholder="输入关键词搜索页面",
                                            options=[
                                                {
                                                    "label": title,
                                                    "value": f"{pathname}|{title}",
                                                }
                                                for pathname, title in RouterConfig.valid_pathnames.items()
                                                # 忽略重复的首页备选地址
                                                if pathname
                                                != RouterConfig.index_pathname
                                            ],
                                            variant="filled",
                                            style=style(width=250),
                                        ),
                                        fac.AntdText(
                                            [
                                                fac.AntdText(
                                                    "Ctrl",
                                                    keyboard=True,
                                                    className="global-help-text",
                                                ),
                                                fac.AntdText(
                                                    "K",
                                                    keyboard=True,
                                                    className="global-help-text",
                                                ),
                                            ]
                                        ),
                                    ],
                                    size=5,
                                ),
                                # 功能图标+用户信息
                                fac.AntdSpace(
                                    [
                                        # 示例功能图标1
                                        fac.AntdButton(
                                            icon=fac.AntdIcon(
                                                icon="antd-setting",
                                                className="global-help-text",
                                            ),
                                            type="text",
                                        ),
                                        # 示例功能图标2
                                        fac.AntdButton(
                                            icon=fac.AntdIcon(
                                                icon="antd-bell",
                                                className="global-help-text",
                                            ),
                                            type="text",
                                        ),
                                        # 示例功能图标3
                                        fac.AntdButton(
                                            icon=fac.AntdIcon(
                                                icon="antd-question-circle",
                                                className="global-help-text",
                                            ),
                                            type="text",
                                        ),
                                        # 自定义分隔符
                                        html.Div(
                                            style=style(
                                                width=0,
                                                height=42,
                                                borderLeft="1px solid #e1e5ee",
                                                margin="0 12px",
                                            )
                                        ),
                                        # 用户头像
                                        fac.AntdAvatar(
                                            mode="text",
                                            text="🤩",
                                            size=36,
                                            style=style(background="#f4f6f9"),
                                        ),
                                        # 用户名+角色
                                        fac.AntdFlex(
                                            [
                                                fac.AntdText(
                                                    current_user.user_name.capitalize(),
                                                    strong=True,
                                                ),
                                                fac.AntdText(
                                                    "角色：{}".format(
                                                        "系统管理员"
                                                        if current_user.user_role
                                                        == "admin"
                                                        else "常规用户"
                                                    ),
                                                    className="global-help-text",
                                                    style=style(fontSize=12),
                                                ),
                                            ],
                                            vertical=True,
                                        ),
                                        # 用户管理菜单
                                        fac.AntdDropdown(
                                            fac.AntdButton(
                                                icon=fac.AntdIcon(
                                                    icon="antd-more",
                                                    className="global-help-text",
                                                ),
                                                type="text",
                                            ),
                                            id="core-pages-header-user-dropdown",
                                            menuItems=[
                                                {
                                                    "title": "个人信息",
                                                    "key": "个人信息",
                                                },
                                                # 若当前用户角色为系统管理员
                                                *(
                                                    [
                                                        {
                                                            "title": "用户管理",
                                                            "key": "用户管理",
                                                        }
                                                    ]
                                                    if current_user.user_role == "admin"
                                                    else []
                                                ),
                                                {"isDivider": True},
                                                {
                                                    "title": "退出登录",
                                                    "href": "/logout",
                                                },
                                            ],
                                            trigger="click",
                                        ),
                                    ]
                                ),
                            ],
                            justify="space-between",
                            align="center",
                            style=style(
                                height="100%",
                                paddingLeft=20,
                                paddingRight=20,
                            ),
                        ),
                        flex="auto",
                    ),
                ],
                wrap=False,
                align="middle",
                style=style(
                    height=72,
                    borderBottom="1px solid #dae0ea",
                    position="sticky",
                    top=0,
                    zIndex=1000,
                    background="#fff",
                ),
            ),
            # 主题区域
            fac.AntdRow(
                [
                    # 侧边栏
                    fac.AntdCol(
                        core_side_menu.render(),
                        flex="none",
                    ),
                    # 内容区域
                    fac.AntdCol(
                        fac.AntdSkeleton(
                            html.Div(
                                id="core-container", style=style(padding="36px 42px")
                            ),
                            listenPropsMode="include",
                            includeProps=["core-container.children"],
                            active=True,
                            style=style(padding="36px 42px"),
                        ),
                        flex="auto",
                    ),
                ],
                wrap=False,
            ),
        ]
    )