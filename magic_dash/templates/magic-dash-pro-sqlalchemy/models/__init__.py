from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

# 创建数据库引擎
engine = create_engine('sqlite:///magic_dash.db')

# 创建Session工厂
db = scoped_session(sessionmaker(bind=engine))

# 创建声明基类
Base = declarative_base()
Base.query = db.query_property()
