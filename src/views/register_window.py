#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
注册窗口模块
处理用户注册界面和逻辑
"""

import os
import sys
import cv2
import numpy as np
import traceback
import pymysql
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit, 
    QPushButton, QApplication, QMessageBox, QGridLayout
)
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

from ..auth.authenticator import Authenticator
from ..utils.logger import get_logger
from ..utils.validators import validate_register_form
from ..detection.face_utils import check_face_quality
from .components.message_box import MessageBox

logger = get_logger('face_auth')

# 导入其他必要的模块
import time
import threading

class RegisterUserThread(QThread):
    """用户注册线程"""
    finished = pyqtSignal(bool, str)  # 注册结果信号
    
    def __init__(self, authenticator: Authenticator, user_info: dict):
        super().__init__()
        self.authenticator = authenticator
        self.user_info = user_info
    
    def run(self):
        """运行注册线程"""
        try:
            result = self.authenticator.register_user(**self.user_info)
            self.finished.emit(result, "注册成功" if result else "用户名已存在")
        except Exception as e:
            self.finished.emit(False, str(e))

class RegisterFaceThread(QThread):
    """人脸注册线程"""
    finished = pyqtSignal(bool, str)  # 成功/失败，消息
    
    def __init__(self, authenticator, username, frame):
        super().__init__()
        self.authenticator = authenticator
        self.username = username
        self.frame = frame
    
    def run(self):
        """运行人脸注册线程"""
        try:
            result = self.authenticator.register_face(self.username, self.frame)
            if result:
                self.finished.emit(True, "人脸注册成功")
            else:
                self.finished.emit(False, "人脸注册失败，请确保人脸清晰可见")
        except Exception as e:
            self.finished.emit(False, str(e))

class CameraThread(QThread):
    """摄像头线程"""
    frame_ready = pyqtSignal(np.ndarray)  # 帧准备好的信号
    error = pyqtSignal(str)  # 错误信号
    started = pyqtSignal()  # 摄像头启动成功信号
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.cap = None
    
    def run(self):
        """运行摄像头线程"""
        try:
            # 打开摄像头
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                self.error.emit("无法打开摄像头")
                return
            
            self.running = True
            self.started.emit()  # 发送启动成功信号
            
            while self.running:
                ret, frame = self.cap.read()
                if not ret:
                    self.error.emit("无法获取摄像头画面")
                    break
                
                # 发送帧信号
                self.frame_ready.emit(frame)
                
                # 控制帧率
                time.sleep(0.03)  # ~30fps
        
        except Exception as e:
            self.error.emit(f"摄像头线程出错: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        """停止摄像头线程"""
        self.running = False
        if self.cap and self.cap.isOpened():
            self.cap.release()
            self.cap = None

class RegisterWindow(QWidget):
    """注册窗口类"""
    
    # 添加注册成功信号
    register_success = pyqtSignal()
    
    def __init__(self, db_config=None, parent=None):
        super().__init__(parent)
        self.initialization_error = False
        self.error_message = ""
        
        # 设置窗口标题和大小
        self.setWindowTitle('用户注册')
        self.resize(800, 500)
        
        # 设置窗口标志，确保窗口独立显示
        self.setWindowFlags(self.windowFlags() | Qt.Window)
        
        try:
            logger.info("正在初始化注册窗口...")
            
            # 处理参数
            if isinstance(db_config, Authenticator):
                # 如果传入的是Authenticator实例，直接使用
                logger.info("使用传入的Authenticator实例")
                self.authenticator = db_config
            else:
            # 设置默认数据库配置
            if db_config is None:
                from ..config import DB_CONFIG
                db_config = DB_CONFIG
                logger.info("使用默认数据库配置")
            
            # 初始化认证器
            logger.info("正在初始化认证器...")
            self.authenticator = Authenticator(db_config)
            
            # 测试数据库连接
            logger.info("正在测试数据库连接...")
            if not self.authenticator.db.conn or not self.authenticator.db.conn.open:
                raise pymysql.err.OperationalError("数据库连接失败")
            
            # 初始化线程
            self.register_thread = None
            self.face_register_thread = None
            self.camera_thread = None
            self.current_frame = None
            self.current_username = None  # 用于重新录入人脸时存储用户名
            
            # 初始化UI
            logger.info("正在初始化UI...")
            self.init_ui()
            logger.info("注册窗口初始化完成")
            
            # 相对于父窗口偏移显示
            if parent:
                parent_pos = parent.pos()
                x = parent_pos.x() + 50  # 向右偏移50像素
                y = parent_pos.y() + 50  # 向下偏移50像素
                self.move(x, y)
            else:
                self.center_window()
            
        except Exception as e:
            self.error_message = f"初始化失败: {str(e)}"
            logger.error(f"{self.error_message}\n{traceback.format_exc()}")
            self.initialization_error = True
            # 创建一个基本的UI，只显示错误信息
            self.init_error_ui()
            # 确保错误消息能够显示
            QTimer.singleShot(100, self.show_error_message)
    
    def show_error_message(self):
        """显示错误消息"""
        QMessageBox.critical(self, '错误', self.error_message)
        # 如果是初始化错误，关闭窗口
        if self.initialization_error:
            self.close()
    
    def init_error_ui(self):
        """初始化错误UI"""
        # 创建一个简单的布局
        layout = QVBoxLayout()
        
        # 错误消息标签
        error_label = QLabel(self.error_message)
        error_label.setWordWrap(True)
        error_label.setStyleSheet("color: red;")
        layout.addWidget(error_label)
        
        # 确定按钮
        ok_button = QPushButton("确定")
        ok_button.clicked.connect(lambda: self.close())
        layout.addWidget(ok_button)
        
        # 设置布局
        self.setLayout(layout)
        self.setWindowTitle("错误")
        self.resize(400, 200)
        
        # 将窗口移动到屏幕中央
        self.center_window()
    
    def center_window(self):
        """将窗口移动到屏幕中央"""
        screen = QApplication.primaryScreen().geometry()
        size = self.geometry()
        x = (screen.width() - size.width()) // 2
        y = (screen.height() - size.height()) // 2
        self.move(x, y)
    
    def init_ui(self):
        """初始化UI界面"""
        # 创建主布局
        main_layout = QHBoxLayout()
        
        # 左侧布局（注册表单）
        left_layout = QVBoxLayout()
        
        # 创建表单布局
        form_layout = QFormLayout()
        
        # 用户名输入
        self.username_input = QLineEdit()
        self.username_label = QLabel('用户名:')
        form_layout.addRow(self.username_label, self.username_input)
        
        # 密码输入
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_label = QLabel('密码:')
        form_layout.addRow(self.password_label, self.password_input)
        
        # 确认密码输入
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_label = QLabel('确认密码:')
        form_layout.addRow(self.confirm_password_label, self.confirm_password_input)
        
        # 电子邮件输入
        self.email_input = QLineEdit()
        self.email_label = QLabel('电子邮件:')
        form_layout.addRow(self.email_label, self.email_input)
        
        # 手机号码输入
        self.phone_input = QLineEdit()
        self.phone_label = QLabel('手机号码:')
        form_layout.addRow(self.phone_label, self.phone_input)
        
        # 姓名输入
        self.fullname_input = QLineEdit()
        self.fullname_label = QLabel('姓名:')
        form_layout.addRow(self.fullname_label, self.fullname_input)
        
        # 添加表单到左侧布局
        left_layout.addLayout(form_layout)
        
        # 按钮布局
        self.button_layout = QGridLayout()
        
        # 注册按钮
        self.register_button = QPushButton('注册账号')
        self.register_button.clicked.connect(self.register_user)
        
        # 人脸注册按钮
        self.face_register_button = QPushButton('注册人脸')
        self.face_register_button.clicked.connect(self.register_face)
        
        # 返回登录按钮
        self.back_button = QPushButton('返回登录')
        self.back_button.clicked.connect(self.close)
        
        # 开始/停止摄像头按钮
        self.camera_button = QPushButton('开启摄像头')
        self.camera_button.clicked.connect(self.toggle_camera)
        
        # 添加按钮到网格布局
        self.button_layout.addWidget(self.register_button, 0, 0)
        self.button_layout.addWidget(self.face_register_button, 0, 1)
        self.button_layout.addWidget(self.camera_button, 1, 0, 1, 2)
        self.button_layout.addWidget(self.back_button, 2, 0, 1, 2)
        
        # 添加按钮布局到左侧布局
        left_layout.addLayout(self.button_layout)
        left_layout.addStretch()
        
        # 右侧布局（摄像头预览）
        right_layout = QVBoxLayout()
        
        # 摄像头标签
        self.camera_label = QLabel('摄像头预览')
        self.camera_label.setAlignment(Qt.AlignCenter)
        self.camera_label.setMinimumSize(400, 300)
        self.camera_label.setStyleSheet("border: 1px solid #cccccc;")
        
        # 状态标签
        self.status_label = QLabel('请填写注册信息')
        self.status_label.setAlignment(Qt.AlignCenter)
        
        # 添加控件到右侧布局
        right_layout.addWidget(self.camera_label)
        right_layout.addWidget(self.status_label)
        
        # 将左右布局添加到主布局
        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 2)
        
        # 设置主布局
        self.setLayout(main_layout)
        
        # 如果是重新录入人脸模式
        if hasattr(self, 'current_username') and self.current_username:
            # 在UI初始化完成后设置状态标签
            self.status_label.setText(f"为用户 {self.current_username} 重新录入人脸")
            # 自动开启摄像头
            QTimer.singleShot(500, self.toggle_camera)
    
    def toggle_camera(self):
        """开启/关闭摄像头"""
        try:
            if self.camera_thread and self.camera_thread.running:
                logger.info("正在关闭摄像头...")
                # 关闭摄像头
                self.camera_thread.stop()
                self.camera_button.setText('开启摄像头')
                self.camera_label.setText('摄像头已关闭')
                self.current_frame = None
                logger.info("摄像头已关闭")
            else:
                logger.info("正在开启摄像头...")
                # 开启摄像头
                self.camera_button.setEnabled(False)  # 暂时禁用按钮
                self.status_label.setText('正在初始化摄像头...')
                
                # 创建并启动摄像头线程
                self.camera_thread = CameraThread()
                logger.info("摄像头线程已创建")
                self.camera_thread.frame_ready.connect(self.update_frame)
                self.camera_thread.error.connect(self.handle_camera_error)
                self.camera_thread.started.connect(self.on_camera_started)
                logger.info("摄像头线程信号已连接")
                self.camera_thread.start()
                logger.info("摄像头线程已启动")
                
        except Exception as e:
            error_msg = f"摄像头操作失败: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            self.handle_camera_error(error_msg)
    
    def on_camera_started(self):
        """摄像头启动成功的处理"""
        logger.info("摄像头启动成功")
        self.camera_button.setEnabled(True)
        self.camera_button.setText('关闭摄像头')
        self.status_label.setText('摄像头已开启')
    
    def handle_camera_error(self, error_msg):
        """处理摄像头错误"""
        logger.error(f"摄像头错误: {error_msg}")
        self.camera_button.setEnabled(True)
        self.camera_button.setText('开启摄像头')
        self.camera_thread = None  # 清除摄像头线程引用
        MessageBox.warning(self, '提示', f'摄像头错误: {error_msg}')
        self.status_label.setText('摄像头初始化失败')
    
    def update_frame(self, frame):
        """更新摄像头画面"""
        self.current_frame = frame
        
        # 转换为Qt图像
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb_frame.shape
        bytes_per_line = ch * w
        qt_image = QImage(rgb_frame.data, w, h, bytes_per_line, QImage.Format_RGB888)
        
        # 调整大小并显示
        pixmap = QPixmap.fromImage(qt_image)
        pixmap = pixmap.scaled(
            self.camera_label.width(), 
            self.camera_label.height(),
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )
        self.camera_label.setPixmap(pixmap)
    
    def register_user(self):
        """注册用户"""
        try:
            # 如果是重新录入人脸模式
            if self.current_username:
                if self.current_frame is None:
                    logger.warning(f"用户 {self.current_username} 重新录入人脸失败: 未拍摄人脸照片")
                    MessageBox.warning(self, '提示', '请先开启摄像头并确保能看到您的面部')
                    return
                
                # 检查人脸图片是否合规
                is_valid, error_message = check_face_quality(self.current_frame)
                if not is_valid:
                    MessageBox.warning(self, '提示', error_message)
                    return
                
                # 直接注册人脸
                try:
                    logger.info(f"开始为用户 {self.current_username} 重新录入人脸...")
                    if self.authenticator.register_face(self.current_username, self.current_frame):
                        logger.info(f"用户 {self.current_username} 重新录入人脸成功")
                        MessageBox.info(self, '成功', '人脸信息重新录入成功！')
                        self.register_success.emit()
                        self.close()
                    else:
                        error_msg = "人脸录入失败，请确保面部清晰可见"
                        logger.warning(f"用户 {self.current_username} 重新录入人脸失败: {error_msg}")
                        MessageBox.warning(self, '提示', '人脸录入失败，请确保：\n1. 面部清晰可见\n2. 光线适中\n3. 正面面对摄像头')
                except Exception as e:
                    error_msg = f"人脸录入过程出错: {str(e)}"
                    logger.error(f"{error_msg}\n{traceback.format_exc()}")
                    MessageBox.error(self, '系统提示', '人脸录入过程出现错误，请重试。如果问题持续存在，请联系系统管理员。')
                return
            
            # 正常注册流程
            username = self.username_input.text().strip()
            password = self.password_input.text()
            confirm_password = self.confirm_password_input.text()
            email = self.email_input.text().strip()
            phone = self.phone_input.text().strip()
            
            logger.info(f"开始注册新用户: {username}, 邮箱: {email}, 手机: {phone}")
            
            # 验证表单
            valid, error_message = validate_register_form(username, password, confirm_password, email, phone)
            if not valid:
                logger.warning(f"用户 {username} 注册表单验证失败: {error_message}")
                MessageBox.warning(self, '表单验证失败', error_message)
                return
            
            # 注册用户
            logger.info(f"正在创建用户: {username}")
            if self.authenticator.register_user(username, password, email, phone):
                logger.info(f"用户 {username} 创建成功")
                MessageBox.info(self, '成功', '账号创建成功！请继续录入人脸信息。')
                
                # 禁用账号注册相关控件
                self.username_input.setEnabled(False)
                self.password_input.setEnabled(False)
                self.confirm_password_input.setEnabled(False)
                self.email_input.setEnabled(False)
                self.phone_input.setEnabled(False)
                self.register_button.setEnabled(False)
                
                # 保存当前用户名，进入人脸注册模式
                self.current_username = username
                
                # 提示用户进行人脸注册
                self.status_label.setText('请点击"开启摄像头"并进行人脸录入')
                
                # 如果摄像头未开启，自动开启
                if not self.camera_thread or not self.camera_thread.running:
                    self.toggle_camera()
            else:
                logger.warning(f"用户名 {username} 已存在")
                MessageBox.warning(self, '提示', '用户名已存在，请尝试使用其他用户名')
        except Exception as e:
            logger.error(f"注册过程出错: {str(e)}\n{traceback.format_exc()}")
            MessageBox.error(self, '系统提示', '注册过程出现错误，请重试。如果问题持续存在，请联系系统管理员。')
    
    def register_face(self):
        """注册人脸"""
        # 使用当前用户名或输入框中的用户名
        username = self.current_username or self.username_input.text().strip()
        
        if not username:
            MessageBox.warning(self, '提示', '请先完成账号注册')
            return
        
        if not self.camera_thread or not self.camera_thread.running:
            MessageBox.warning(self, '提示', '请先点击"开启摄像头"按钮')
            return
        
        if self.current_frame is None:
            MessageBox.warning(self, '提示', '等待摄像头画面，请确保摄像头已正确连接并开启')
            return
        
        # 检查人脸图片质量
        is_valid, error_message = check_face_quality(self.current_frame)
        if not is_valid:
            MessageBox.warning(self, '提示', error_message)
            return
        
        # 禁用人脸注册按钮
        self.face_register_button.setEnabled(False)
        self.status_label.setText('正在注册人脸...')
        
        logger.info(f"开始为用户 {username} 注册人脸...")
        
        # 创建并启动人脸注册线程
        self.face_register_thread = RegisterFaceThread(
            self.authenticator, username, self.current_frame.copy()
        )
        self.face_register_thread.finished.connect(self.on_face_register_finished)
        self.face_register_thread.start()
    
    def on_face_register_finished(self, success, message):
        """人脸注册完成回调"""
        # 恢复人脸注册按钮
        self.face_register_button.setEnabled(True)
        
        if success:
            logger.info(f"用户 {self.current_username or self.username_input.text().strip()} 人脸注册成功")
            MessageBox.info(self, '注册成功', '您的人脸信息已成功录入系统！')
            self.register_success.emit()  # 发送注册成功信号
            self.close()  # 关闭注册窗口
        else:
            logger.warning(f"用户 {self.current_username or self.username_input.text().strip()} 人脸注册失败: {message}")
            MessageBox.warning(self, '提示', '人脸注册失败，请确保：\n1. 面部清晰可见\n2. 光线适中\n3. 正面面对摄像头\n\n请调整后重试。')
            self.status_label.setText('人脸注册失败，请重试')
    
    def showEvent(self, event):
        """窗口显示事件"""
        super().showEvent(event)
        logger.info(f"注册窗口显示事件触发，initialization_error={self.initialization_error}")
        
        # 确保窗口显示在前台
        self.raise_()
        self.activateWindow()
        
        # 不再禁用父窗口，因为这会导致子窗口也被禁用
        # if self.parent() and not self.initialization_error:
        #     self.parent().setEnabled(False)
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        logger.info("注册窗口关闭事件触发")
        try:
            # 关闭摄像头线程
            if hasattr(self, 'camera_thread') and self.camera_thread and self.camera_thread.running:
                logger.info("正在关闭摄像头...")
                self.camera_thread.stop()
                logger.info("摄像头已关闭")
            
            # 如果有父窗口，激活它
            if self.parent():
                self.parent().activateWindow()
        except Exception as e:
            logger.error(f"关闭摄像头失败: {str(e)}")
        finally:
            event.accept() 