from typing import List, Union


class BaseConfig:
    """应用基础配置参数"""

    # 应用基础标题
    app_title: str = "Magic Dash Pro"

    # 应用版本
    app_version: str = "0.2.8"

    # 应用密钥
    app_secret_key: str = "magic-dash-pro-demo"

    # 浏览器最低版本限制规则
    min_browser_versions: List[dict] = [
        {"browser": "Chrome", "version": 88},
        {"browser": "Firefox", "version": 78},
        {"browser": "Edge", "version": 100},
    ]

    # 是否基于min_browser_versions开启严格的浏览器类型限制
    # 不在min_browser_versions规则内的浏览器将被直接拦截
    strict_browser_type_check: bool = False

    # 是否启用重复登录辅助检查
    enable_duplicate_login_check: bool = True

    # 重复登录辅助检查轮询间隔时间，单位：秒
    duplicate_login_check_interval: Union[int, float] = 10
