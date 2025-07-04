#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件
存储全局配置参数
"""

import os
import logging
import sys
from datetime import datetime

# 项目根目录
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 资源目录
RESOURCES_DIR = os.path.join(ROOT_DIR, 'resources')
ICONS_DIR = os.path.join(RESOURCES_DIR, 'icons')
STYLES_DIR = os.path.join(RESOURCES_DIR, 'styles')
MODELS_DIR = os.path.join(RESOURCES_DIR, 'models')

# 日志目录
LOGS_DIR = os.path.join(ROOT_DIR, 'logs')

# 确保资源目录存在
try:
    os.makedirs(RESOURCES_DIR, exist_ok=True)
    os.makedirs(ICONS_DIR, exist_ok=True)
    os.makedirs(STYLES_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
except Exception as e:
    print(f"错误: 无法创建必要的资源目录: {str(e)}")
    sys.exit(1)

# 日志配置
LOG_LEVEL = logging.DEBUG if '--debug' in sys.argv else logging.INFO
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# 根据日期生成日志文件名
date_str = datetime.now().strftime('%Y%m%d')
LOG_FILE = os.path.join(LOGS_DIR, f'face_auth_{date_str}.log')

# 日志配置选项
LOG_CONFIG = {
    'max_bytes': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
    'encoding': 'utf-8',
    'console_level': LOG_LEVEL,
    'file_level': logging.DEBUG,  # 文件始终记录DEBUG级别
    'log_dir': LOGS_DIR,  # 添加日志目录配置
    'retention_days': 30,  # 日志保留天数
}

# 数据库配置
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',  # 请修改为你的MySQL密码
    'db_name': 'face_auth',
    'port': 3306,
    'charset': 'utf8mb4',
    'connect_timeout': 5,  # 连接超时时间（秒）
    'max_retries': 3,      # 最大重试次数
}

# 人脸识别配置
FACE_DETECTION = {
    'min_face_size': 20,
    'image_size': 160,
    'margin': 20,
    'threshold': 0.7,  # 人脸匹配阈值
    'use_cuda': True,  # 是否使用GPU
    'timeout': 30,     # 检测超时时间（秒）
    'max_retries': 3,  # 最大重试次数
    'min_detection_confidence': 0.7,  # 最小检测置信度
}

# UI配置
UI_CONFIG = {
    'window_title': '人脸识别双因素认证系统',
    'window_width': 800,
    'window_height': 500,
    'camera_width': 400,
    'camera_height': 300,
    'camera_fps': 30,
    'style_sheet': 'default',  # 样式表名称
    'timeout': {
        'login': 60,    # 登录超时时间（秒）
        'register': 120, # 注册超时时间（秒）
        'face_scan': 30, # 人脸扫描超时时间（秒）
    },
    'error_display_time': 5000,  # 错误消息显示时间（毫秒）
}

# 错误消息
ERROR_MESSAGES = {
    'db_connection': '数据库连接失败，请检查配置和确保MySQL服务已启动',
    'camera_init': '无法初始化摄像头，请检查设备连接',
    'face_detection': '人脸检测失败，请确保光线充足且正面对着摄像头',
    'login_timeout': '登录超时，请重试',
    'register_timeout': '注册超时，请重试',
    'face_scan_timeout': '人脸扫描超时，请重试',
    'invalid_credentials': '用户名或密码错误',
    'face_mismatch': '人脸验证失败，请重试',
    'system_error': '系统错误，请查看日志获取详细信息',
}

# 版本信息
VERSION = '1.0.0'

# 调试模式标志
DEBUG = '--debug' in sys.argv 