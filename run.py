#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
人脸识别+账号密码双要素登录系统
启动脚本
"""

import os
import sys
import argparse

# 将当前目录添加到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='人脸识别+账号密码双要素登录系统')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--host', default='localhost', help='MySQL主机地址')
    parser.add_argument('--user', default='root', help='MySQL用户名')
    parser.add_argument('--password', default='123456', help='MySQL密码')
    parser.add_argument('--db', default='face_auth', help='MySQL数据库名')
    
    args = parser.parse_args()
    
    try:
        from src.config import DB_CONFIG
        
        # 更新数据库配置
        DB_CONFIG.update({
            'host': args.host,
            'user': args.user,
            'password': args.password,
            'db_name': args.db
        })
        
        # 导入并运行主程序
        from src.main import main as run_app
        run_app(debug=args.debug, db_config=DB_CONFIG)
    except ImportError as e:
        print(f"导入错误: {e}")
        print("请确保已安装所有依赖，可以运行 'pip install -r requirements.txt'")
        sys.exit(1)
    except Exception as e:
        print(f"程序运行出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 