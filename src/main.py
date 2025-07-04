#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
人脸识别+账号密码双要素登录系统
主程序入口

技术栈:
- Python 3.8.10
- PyTorch 1.10.1
- MTCNN (facenet-pytorch 2.5.2)
- OpenCV 4.5.5.64
- NumPy 1.21.6
- PyQt5 5.15.9
- PyQt5-sip 12.12.1
- MySQL 5.7.20
"""

import warnings
warnings.filterwarnings('ignore', message='loaded more than 1 DLL from .libs')

import sys
import os
import logging
import argparse
import traceback
from datetime import datetime

# 将项目根目录添加到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# 设置异常钩子，捕获未处理的异常
def exception_hook(exctype, value, tb):
    """全局异常处理钩子"""
    error_msg = ''.join(traceback.format_exception(exctype, value, tb))
    print(f"未捕获的异常: {error_msg}")
    
    # 如果日志系统已经初始化，记录到日志
    if 'logger' in globals():
        logger.critical(f"未捕获的异常: {error_msg}")
    
    # 调用原始的异常处理器
    sys.__excepthook__(exctype, value, tb)

# 设置异常钩子
sys.excepthook = exception_hook

from PyQt5.QtWidgets import QApplication, QMessageBox
from src.views.login_window import LoginWindow
from src.utils.logger import setup_logger, get_logger

def check_imports():
    """检查所有必要的导入"""
    try:
        print("检查必要的导入...")
        # 基础库
        import numpy
        print("✓ NumPy 已导入")
        import cv2
        print("✓ OpenCV 已导入")
        import torch
        print("✓ PyTorch 已导入")
        
        # PyQt5 相关
        from PyQt5 import QtCore, QtGui, QtWidgets
        print("✓ PyQt5 核心组件已导入")
        
        # 项目模块
        from src.auth.authenticator import Authenticator
        print("✓ Authenticator 已导入")
        from src.detection.face_detector import FaceDetector
        print("✓ FaceDetector 已导入")
        from src.detection.face_utils import check_face_quality
        print("✓ face_utils 已导入")
        from src.database.db_helper import DBHelper
        print("✓ DBHelper 已导入")
        from src.utils.validators import validate_login_form, validate_register_form
        print("✓ validators 已导入")
        from src.views.components.message_box import MessageBox
        print("✓ MessageBox 已导入")
        
        return True
    except ImportError as e:
        print(f"导入错误: {str(e)}")
        if 'logger' in globals():
            logger.critical(f"导入错误: {str(e)}")
        return False
    except Exception as e:
        print(f"检查导入时出现未知错误: {str(e)}")
        if 'logger' in globals():
            logger.critical(f"检查导入时出现未知错误: {str(e)}\n{traceback.format_exc()}")
        return False

def check_environment():
    """检查运行环境"""
    try:
        import torch
        import cv2
        import numpy
        import facenet_pytorch
        import pymysql
        
        logger.info(f"Python 版本: {sys.version}")
        logger.info(f"PyTorch 版本: {torch.__version__}")
        logger.info(f"OpenCV 版本: {cv2.__version__}")
        logger.info(f"NumPy 版本: {numpy.__version__}")
        logger.info(f"PyMySQL 版本: {pymysql.__version__}")
        
        # 检查CUDA是否可用
        if torch.cuda.is_available():
            logger.info(f"CUDA 可用: {torch.cuda.get_device_name(0)}")
        else:
            logger.info("CUDA 不可用，使用CPU模式")
            
        # 检查摄像头
        cap = cv2.VideoCapture(0)
        if cap.isOpened():
            logger.info("摄像头检查通过")
            cap.release()
        else:
            logger.warning("无法访问摄像头，请检查设备连接")
            
        return True
    except Exception as e:
        logger.error(f"环境检查失败: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def check_database(config):
    """检查数据库连接"""
    try:
        import pymysql
        conn = pymysql.connect(
            host=config['host'],
            user=config['user'],
            password=config['password'],
            database=config['db_name']
        )
        conn.close()
        logger.info("数据库连接测试成功")
        return True
    except Exception as e:
        logger.error(f"数据库连接失败: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def show_error(title, message):
    """显示错误对话框"""
    try:
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        QMessageBox.critical(None, title, message)
    except Exception as e:
        logger.error(f"显示错误对话框失败: {str(e)}")
        print(f"错误: {title} - {message}")

def main(debug=False, db_config=None):
    """主函数"""
    try:
        # 初始化日志
        global logger
        logger = get_logger('main')
        logger.info("程序启动...")
        logger.info(f"调试模式: {'开启' if debug else '关闭'}")
        
        # 检查导入
        if not check_imports():
            show_error("导入错误", "导入必要模块失败，请检查依赖项是否正确安装")
            return 1
        
        # 检查运行环境
        if not check_environment():
            show_error("环境错误", "运行环境检查失败，请查看日志获取详细信息")
            return 1
            
        # 检查数据库配置
        if db_config is None:
            db_config = {
                'host': 'localhost',
                'user': 'root',
                'password': '123456',
                'db_name': 'face_auth',
                'port': 3306,
                'charset': 'utf8mb4',
                'connect_timeout': 5,
                'max_retries': 3
            }
        
        # 测试数据库连接
        if not check_database(db_config):
            show_error("数据库错误", "无法连接到数据库，请检查配置和确保MySQL服务已启动")
            return 1
            
        logger.info(f"使用数据库配置: {db_config}")
        
        # 创建应用
        try:
            logger.info("正在创建QApplication实例...")
            app = QApplication(sys.argv)
            logger.info("QApplication实例创建成功")
        except Exception as e:
            error_msg = f"创建QApplication实例失败: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            show_error("启动错误", error_msg)
            return 1
        
        # 创建并显示登录窗口
        try:
            logger.info("正在创建登录窗口...")
            window = LoginWindow(db_config)
            logger.info("登录窗口创建成功，准备显示...")
            window.show()
            logger.info("登录窗口已显示")
            
            # 运行应用
            logger.info("开始运行应用事件循环...")
            result = app.exec_()
            logger.info(f"应用事件循环结束，返回值: {result}")
            return result
            
        except Exception as e:
            error_msg = f"创建或显示登录窗口失败: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            show_error("启动错误", error_msg)
            return 1
            
    except Exception as e:
        error_msg = f"程序运行出错: {str(e)}"
        if 'logger' in globals():
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
        else:
            print(f"{error_msg}\n{traceback.format_exc()}")
        show_error("严重错误", error_msg)
        return 1

if __name__ == "__main__":
    try:
        # 解析命令行参数
        parser = argparse.ArgumentParser(description='人脸识别+账号密码双要素登录系统')
        parser.add_argument('--debug', action='store_true', help='启用调试模式')
        parser.add_argument('--host', default='localhost', help='MySQL主机地址')
        parser.add_argument('--user', default='root', help='MySQL用户名')
        parser.add_argument('--password', default='123456', help='MySQL密码')
        parser.add_argument('--db', default='face_auth', help='MySQL数据库名')
        
        args = parser.parse_args()
        
        # 配置数据库
        db_config = {
            'host': args.host,
            'user': args.user,
            'password': args.password,
            'db_name': args.db
        }
        
        # 运行主程序
        sys.exit(main(debug=args.debug, db_config=db_config))
        
    except Exception as e:
        print(f"启动失败: {str(e)}")
        traceback.print_exc()
        sys.exit(1) 