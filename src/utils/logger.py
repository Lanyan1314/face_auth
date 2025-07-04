#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
日志工具
提供统一的日志记录功能
"""

import os
import logging
from logging.handlers import RotatingFileHandler
import sys
import datetime
import traceback
import glob
import time

from ..config import LOG_LEVEL, LOG_FILE, LOG_CONFIG

# 自定义的日志格式，包含更多上下文信息
LOG_FORMAT = '%(asctime)s [%(levelname)s] [%(name)s] [%(filename)s:%(lineno)d] - %(message)s'

class CustomFormatter(logging.Formatter):
    """自定义日志格式化器，添加颜色支持"""
    
    grey = "\x1b[38;21m"
    blue = "\x1b[34;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        
        # 如果是异常，添加完整的堆栈跟踪
        if record.exc_info:
            record.exc_text = ''.join(traceback.format_exception(*record.exc_info))
        
        return formatter.format(record)

def cleanup_old_logs():
    """
    清理过期的日志文件
    根据配置的保留天数删除旧的日志文件
    """
    try:
        retention_days = LOG_CONFIG.get('retention_days', 30)
        log_dir = LOG_CONFIG.get('log_dir')
        if not log_dir or not os.path.exists(log_dir):
            return
            
        # 获取当前时间戳
        current_time = time.time()
        # 获取所有日志文件
        log_files = glob.glob(os.path.join(log_dir, 'face_auth_*.log*'))
        
        for log_file in log_files:
            try:
                # 获取文件的修改时间
                file_time = os.path.getmtime(log_file)
                # 如果文件超过保留天数，则删除
                if (current_time - file_time) > (retention_days * 24 * 60 * 60):
                    os.remove(log_file)
            except Exception as e:
                print(f"清理日志文件 {log_file} 时出错: {str(e)}")
                
    except Exception as e:
        print(f"清理日志文件时出错: {str(e)}")

def setup_logger(name, level=None, log_file=None):
    """
    设置日志记录器
    :param name: 日志记录器名称
    :param level: 日志级别，默认使用配置文件中的级别
    :param log_file: 日志文件路径，默认使用配置文件中的路径
    :return: 日志记录器对象
    """
    level = level or LOG_LEVEL
    log_file = log_file or LOG_FILE
    
    # 创建日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 如果已经有处理器，则不重复添加
    if logger.handlers:
        return logger
    
    try:
        # 清理旧的日志文件
        cleanup_old_logs()
        
        # 创建控制台处理器（带颜色）
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(LOG_CONFIG.get('console_level', level))
        console_handler.setFormatter(CustomFormatter(LOG_FORMAT))
        logger.addHandler(console_handler)
        
        # 确保日志目录存在
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # 根据日期创建日志文件
        date_str = datetime.datetime.now().strftime('%Y%m%d')
        base_name, ext = os.path.splitext(log_file)
        dated_log_file = f"{base_name}_{date_str}{ext}"
        
        # 创建滚动文件处理器
        file_handler = RotatingFileHandler(
            dated_log_file,
            maxBytes=LOG_CONFIG.get('max_bytes', 10*1024*1024),  # 默认10MB
            backupCount=LOG_CONFIG.get('backup_count', 5),
            encoding=LOG_CONFIG.get('encoding', 'utf-8')
        )
        file_handler.setLevel(LOG_CONFIG.get('file_level', level))
        file_formatter = logging.Formatter(LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        logger.info(f"日志记录器 '{name}' 初始化成功，日志文件: {dated_log_file}")
        
    except Exception as e:
        # 确保至少控制台输出是可用的
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(console_handler)
        logger.error(f"初始化日志系统时出错: {str(e)}")
        logger.error(traceback.format_exc())
    
    return logger

# 创建默认日志记录器
logger = setup_logger('face_auth')

def get_logger(name):
    """
    获取指定名称的日志记录器
    :param name: 日志记录器名称
    :return: 日志记录器对象
    """
    return setup_logger(f'face_auth.{name}') 