#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据验证工具
验证用户输入
"""

import re
from .logger import get_logger

logger = get_logger('validators')

def validate_username(username):
    """
    验证用户名
    规则：
    1. 长度在3-20个字符之间
    2. 只能包含字母、数字、下划线
    3. 必须以字母开头
    :param username: 用户名
    :return: (是否有效, 错误信息)
    """
    if not username:
        return False, "用户名不能为空，请输入用户名"
    
    if len(username) < 3 or len(username) > 20:
        return False, "用户名长度必须在3-20个字符之间，当前长度：" + str(len(username))
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
        return False, "用户名格式不正确，只能包含字母、数字、下划线，且必须以字母开头"
    
    return True, ""

def validate_password(password):
    """
    验证密码
    规则：
    1. 长度在6-20个字符之间
    2. 必须包含至少一个字母和一个数字
    :param password: 密码
    :return: (是否有效, 错误信息)
    """
    if not password:
        return False, "密码不能为空，请输入密码"
    
    if len(password) < 6 or len(password) > 20:
        return False, "密码长度必须在6-20个字符之间，当前长度：" + str(len(password))
    
    if not re.search(r'[a-zA-Z]', password) or not re.search(r'[0-9]', password):
        return False, "密码必须同时包含字母和数字，以增强安全性"
    
    return True, ""

def validate_email(email):
    """
    验证电子邮件地址
    规则：
    1. 符合标准电子邮件格式
    2. 允许为空（可选字段）
    :param email: 电子邮件地址
    :return: (是否有效, 错误信息)
    """
    if not email:
        return True, ""  # 允许为空
    
    # 使用正则表达式验证电子邮件格式
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "电子邮件格式不正确，请输入有效的电子邮件地址（如：example@domain.com）"
    
    return True, ""

def validate_phone(phone):
    """
    验证手机号码
    规则：
    1. 符合中国大陆手机号格式（11位数字，以1开头）
    2. 允许为空（可选字段）
    :param phone: 手机号码
    :return: (是否有效, 错误信息)
    """
    if not phone:
        return True, ""  # 允许为空
    
    # 使用正则表达式验证手机号格式（中国大陆）
    if not re.match(r'^1[3-9]\d{9}$', phone):
        return False, "手机号格式不正确，请输入11位有效的手机号码（以1开头）"
    
    return True, ""

def validate_login_form(username, password):
    """
    验证登录表单
    :param username: 用户名
    :param password: 密码
    :return: (是否有效, 错误信息)
    """
    logger.info(f"验证登录表单: 用户名={username}")
    
    # 验证用户名
    valid, message = validate_username(username)
    if not valid:
        logger.warning(f"登录表单验证失败: {message}")
        return False, message
    
    # 验证密码
    valid, message = validate_password(password)
    if not valid:
        logger.warning(f"登录表单验证失败: {message}")
        return False, message
    
    logger.info("登录表单验证通过")
    return True, ""

def validate_register_form(username, password, confirm_password, email=None, phone=None):
    """
    验证注册表单
    :param username: 用户名
    :param password: 密码
    :param confirm_password: 确认密码
    :param email: 电子邮件（可选）
    :param phone: 手机号码（可选）
    :return: (是否有效, 错误信息)
    """
    # 记录验证开始
    logger.info(f"开始验证注册表单数据: 用户名={username}, 邮箱={email}, 手机={phone}")
    
    # 验证用户名和密码
    valid, message = validate_login_form(username, password)
    if not valid:
        logger.warning(f"表单验证失败: {message}")
        return False, message
    
    # 验证确认密码
    if password != confirm_password:
        message = "两次输入的密码不一致"
        logger.warning(f"表单验证失败: {message}")
        return False, message
    
    # 验证电子邮件（如果提供）
    if email:
        valid, message = validate_email(email)
        if not valid:
            logger.warning(f"表单验证失败: {message}")
            return False, message
    
    # 验证手机号码（如果提供）
    if phone:
        valid, message = validate_phone(phone)
        if not valid:
            logger.warning(f"表单验证失败: {message}")
            return False, message
    
    logger.info("注册表单验证通过")
    return True, ""

def sanitize_input(text):
    """
    清理输入文本，防止SQL注入和XSS攻击
    :param text: 输入文本
    :return: 清理后的文本
    """
    if not text:
        return ""
    
    # 移除HTML标签
    text = re.sub(r'<[^>]*>', '', text)
    
    # 移除SQL注入相关字符
    text = re.sub(r'[\'";]', '', text)
    
    return text.strip() 