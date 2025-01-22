from typing import Literal


class LayoutConfig:
    """页面布局相关配置参数"""

    # 核心页面侧边栏像素宽度
    core_side_width: int = 350

    # 登录页面左侧内容形式，可选项有'image'（图片内容）、'video'（视频内容）
    login_left_side_content_type: Literal["image", "video"] = "image"
