import time
import dash
from dash import set_props
import feffery_antd_components as fac
from dash.dependencies import Input, Output, State, ClientsideFunction

from server import app
from views.status_pages import _404
from views.core_pages import (
    index,
    page1,
    sub_menu_page1,
    sub_menu_page2,
    sub_menu_page3,
    independent_page,
)

# 路由配置参数
from configs import RouterConfig

app.clientside_callback(
    # 控制核心页面侧边栏折叠
    ClientsideFunction(
        namespace="clientside_basic", function_name="handleSideCollapse"
    ),
    [
        Output("core-side-menu-collapse-button-icon", "icon"),
        Output("core-header-side", "style"),
        Output("core-header-title", "style"),
        Output("core-side-menu-affix", "style"),
        Output("core-side-menu", "inlineCollapsed"),
    ],
    Input("core-side-menu-collapse-button", "nClicks"),
    [
        State("core-side-menu-collapse-button-icon", "icon"),
        State("core-header-side", "style"),
        State("core-page-config", "data"),
    ],
    prevent_initial_call=True,
)

app.clientside_callback(
    # 控制页首页面搜索切换功能
    ClientsideFunction(
        namespace="clientside_basic", function_name="handleCorePageSearch"
    ),
    Input("core-page-search", "value"),
)

app.clientside_callback(
    # 控制ctrl+k快捷键聚焦页面搜索框
    ClientsideFunction(
        namespace="clientside_basic", function_name="handleCorePageSearchFocus"
    ),
    # 其中更新key用于强制刷新状态
    [
        Output("core-page-search", "autoFocus"),
        Output("core-page-search", "key"),
    ],
    Input("core-ctrl-k-key-press", "pressedCounts"),
    prevent_initial_call=True,
)


@app.callback(
    Input("core-pages-header-user-dropdown", "nClicks"),
    State("core-pages-header-user-dropdown", "clickedKey"),
)
def open_user_manage_drawer(nClicks, clickedKey):
    """打开个人信息、用户管理面板"""

    if clickedKey == "个人信息":
        set_props("personal-info-modal", {"visible": True, "loading": True})

    elif clickedKey == "用户管理":
        set_props("user-manage-drawer", {"visible": True, "loading": True})


@app.callback(
    [
        Output("core-container", "children"),
        Output("core-side-menu", "currentKey"),
        Output("core-side-menu", "openKeys"),
    ],
    Input("core-url", "pathname"),
)
def core_router(pathname):
    """核心页面路由控制及侧边菜单同步"""

    # 统一首页pathname
    if pathname == RouterConfig.index_pathname:
        pathname = "/"

    # 若当前目标pathname不合法
    if pathname not in RouterConfig.valid_pathnames.keys():
        return _404.render(), pathname, dash.no_update

    # 增加一点加载动画延迟^_^
    time.sleep(0.5)

    # 初始化页面返回内容
    page_content = fac.AntdAlert(
        type="warning",
        showIcon=True,
        message=f"这里是{pathname}",
        description="该页面尚未进行开发哦🤔~",
    )

    # 以首页做简单示例
    if pathname == "/":
        # 更新页面返回内容
        page_content = index.render()

    # 以主要页面1做简单示例
    elif pathname == "/core/page1":
        # 更新页面返回内容
        page_content = page1.render()

    # 以子菜单演示1做简单示例
    elif pathname == "/core/sub-menu-page1":
        # 更新页面返回内容
        page_content = sub_menu_page1.render()

    # 以子菜单演示2做简单示例
    elif pathname == "/core/sub-menu-page2":
        # 更新页面返回内容
        page_content = sub_menu_page2.render()

    # 以子菜单演示3做简单示例
    elif pathname == "/core/sub-menu-page3":
        # 更新页面返回内容
        page_content = sub_menu_page3.render()

    # 以独立页面做简单示例
    elif pathname == "/core/independent-page":
        # 更新页面返回内容
        page_content = independent_page.render()

    return [
        page_content,
        pathname,
        RouterConfig.side_menu_open_keys.get(pathname, dash.no_update),
    ]
