from configs import AuthConfig
from models import Base, engine
from werkzeug.security import generate_password_hash

# 导入相关数据表模型
from .users import Users

# 创建表（如果表不存在）
Base.metadata.create_all(engine)

if __name__ == "__main__":
    # 初始化管理员用户
    # 命令：python -m models.init_db
    Users.delete_user("admin")
    Users.add_user(
        user_id="admin",
        user_name="admin",
        password_hash=generate_password_hash("admin123"),
        user_role=AuthConfig.admin_role,
    )
    print("管理员用户 admin 初始化完成")
