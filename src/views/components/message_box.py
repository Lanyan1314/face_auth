#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
消息框组件
封装消息提示功能
"""

from PyQt5.QtWidgets import QMessageBox
from ...utils.logger import get_logger

logger = get_logger('message_box')

class MessageBox:
    """消息框组件"""
    
    # 添加标准按钮常量，与 QMessageBox 保持一致
    Ok = QMessageBox.Ok
    Cancel = QMessageBox.Cancel
    Yes = QMessageBox.Yes
    No = QMessageBox.No
    Abort = QMessageBox.Abort
    Retry = QMessageBox.Retry
    Ignore = QMessageBox.Ignore
    
    @staticmethod
    def info(parent, title, message):
        """
        显示信息消息框
        :param parent: 父窗口
        :param title: 标题
        :param message: 消息内容
        """
        logger.info(f"信息消息: {message}")
        QMessageBox.information(parent, title, message)
    
    @staticmethod
    def warning(parent, title, message):
        """
        显示警告消息框
        :param parent: 父窗口
        :param title: 标题
        :param message: 消息内容
        """
        logger.warning(f"警告消息: {message}")
        QMessageBox.warning(parent, title, message)
    
    @staticmethod
    def error(parent, title, message):
        """
        显示错误消息框
        :param parent: 父窗口
        :param title: 标题
        :param message: 消息内容
        """
        logger.error(f"错误消息: {message}")
        QMessageBox.critical(parent, title, message)
    
    @staticmethod
    def question(parent, title, message, buttons=None, default_button=None):
        """
        显示询问消息框
        :param parent: 父窗口
        :param title: 标题
        :param message: 消息内容
        :param buttons: 按钮组合，默认为 Yes|No
        :param default_button: 默认按钮，默认为 No
        :return: 用户点击的按钮
        """
        logger.info(f"询问消息: {message}")
        if buttons is None:
            buttons = QMessageBox.Yes | QMessageBox.No
        if default_button is None:
            default_button = QMessageBox.No
            
        reply = QMessageBox.question(
            parent, title, message, 
            buttons,
            default_button
        )
        return reply
    
    @staticmethod
    def custom(parent, title, message, icon=QMessageBox.Information, buttons=QMessageBox.Ok, default_button=QMessageBox.Ok):
        """
        显示自定义消息框
        :param parent: 父窗口
        :param title: 标题
        :param message: 消息内容
        :param icon: 图标类型
        :param buttons: 按钮组合
        :param default_button: 默认按钮
        :return: 用户点击的按钮
        """
        logger.info(f"自定义消息: {message}")
        msg_box = QMessageBox(parent)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(icon)
        msg_box.setStandardButtons(buttons)
        msg_box.setDefaultButton(default_button)
        return msg_box.exec_() 