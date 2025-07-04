#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
登录窗口模块
处理用户登录界面和逻辑
"""

import os
import sys
import cv2
import numpy as np
import traceback
import pymysql
import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit, 
    QPushButton, QApplication, QMessageBox, QGridLayout, QDialog
)
from PyQt5.QtGui import QImage, QPixmap, QCursor, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
import sip

from ..auth.authenticator import Authenticator
from ..utils.logger import get_logger
from ..utils.validators import validate_login_form, validate_register_form, validate_email
from ..detection.face_utils import check_face_quality
from ..database.models import UserRole
from .components.message_box import MessageBox
from .register_window import RegisterWindow

logger = get_logger('face_auth')

class LoginThread(QThread):
    """登录线程"""
    finished = pyqtSignal(bool, str)  # 成功/失败，消息
    
    def __init__(self, authenticator, username, password):
        super().__init__()
        self.authenticator = authenticator
        self.username = username
        self.password = password
    
    def run(self):
        try:
            # 调用登录方法获取详细结果
            login_result = self.authenticator.login(self.username, self.password)
            
            # 检查登录是否成功
            if login_result['success']:
                self.finished.emit(True, self.username)
            else:
                self.finished.emit(False, login_result['message'])
        except Exception as e:
            logger.error(f"登录线程出错: {str(e)}\n{traceback.format_exc()}")
            self.finished.emit(False, f"登录出错: {str(e)}")

class FaceLoginThread(QThread):
    """人脸登录线程"""
    finished = pyqtSignal(bool, str)  # 成功/失败，消息
    
    def __init__(self, authenticator, frame):
        try:
            logger.info("初始化人脸登录线程...")
            super().__init__()
            
            if authenticator is None:
                raise ValueError("认证器不能为空")
            if frame is None or not isinstance(frame, np.ndarray):
                raise ValueError("无效的图像数据")
            if frame.size == 0:
                raise ValueError("图像数据为空")
            if len(frame.shape) != 3:
                raise ValueError(f"图像维度错误，需要3维(高度,宽度,通道)，实际为{len(frame.shape)}维")
            
            self.authenticator = authenticator
            # 创建图像数据的深拷贝，避免引用原始数据
            self.frame = frame.copy()
            logger.info("人脸登录线程初始化完成")
        except Exception as e:
            error_msg = f"初始化人脸登录线程失败: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            raise RuntimeError(error_msg)
    
    def run(self):
        """运行人脸登录线程"""
        try:
            logger.info("开始执行人脸登录...")
            
            # 验证图像数据
            if self.frame is None:
                raise ValueError("图像数据为空")
            
            # 执行人脸登录
            try:
                logger.info("调用authenticator.face_login...")
                result = self.authenticator.face_login(self.frame)
                logger.info(f"face_login返回结果: {result}")
                
                if result['success']:
                    logger.info(f"人脸登录成功，用户: {result['username']}")
                    logger.info("发送成功信号...")
                    self.finished.emit(True, result['username'])
                else:
                    logger.warning(f"人脸登录失败: {result['message']}")
                    logger.info("发送失败信号...")
                    self.finished.emit(False, result['message'])
            except Exception as e:
                error_msg = f"人脸登录过程出错: {str(e)}"
                logger.error(f"{error_msg}\n{traceback.format_exc()}")
                logger.info("发送错误信号...")
                self.finished.emit(False, error_msg)
                
        except Exception as e:
            error_msg = f"人脸识别出错: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            logger.info("发送异常信号...")
            self.finished.emit(False, error_msg)
        finally:
            # 清理资源
            try:
                self.frame = None
                logger.debug("已清理图像数据")
            except Exception as e:
                logger.error(f"清理资源时出错: {e}")
            logger.info("人脸登录线程执行完成")
    
    def __del__(self):
        """析构函数"""
        try:
            # 确保资源被释放
            if hasattr(self, 'frame') and self.frame is not None:
                self.frame = None
            # 不要在这里访问日志记录器，可能导致闪退
        except Exception:
            # 析构函数中的异常不应该传播
            pass

class CameraThread(QThread):
    """摄像头线程类"""
    frame_ready = pyqtSignal(QImage)
    error = pyqtSignal(str)
    started = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._running = False
        self._capture = None
        self._error_count = 0  # 添加错误计数器
        self._max_errors = 3   # 最大允许的连续错误次数
        self._lock = threading.Lock()  # 添加线程锁以保护共享数据
        logger.info("摄像头线程初始化")
        
    def __del__(self):
        """析构函数"""
        try:
            self._cleanup()
        except Exception:
            # 析构函数中的异常不应该传播
            pass

    def run(self):
        """运行摄像头线程"""
        try:
            logger.info("正在打开摄像头...")
            self._capture = cv2.VideoCapture(0)
            if not self._capture.isOpened():
                logger.error("无法打开摄像头")
                self.error.emit("无法打开摄像头")
                return
            
            logger.info("摄像头已成功打开")
            self._running = True
            with self._lock:
                self._error_count = 0  # 重置错误计数
            self.started.emit()
            
            while self._running and self._capture is not None:
                try:
                    ret, frame = self._capture.read()
                    if not ret or frame is None:
                        with self._lock:
                            self._error_count += 1
                            error_count = self._error_count
                        logger.error(f"无法读取摄像头画面 (错误次数: {error_count})")
                        if error_count >= self._max_errors:
                            self.error.emit("无法读取摄像头画面，请检查摄像头连接")
                            break
                        continue
                    
                    with self._lock:
                        self._error_count = 0  # 成功读取后重置错误计数
                    
                    # 转换图像格式
                    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    h, w, ch = rgb_frame.shape
                    bytes_per_line = ch * w
                    
                    # 创建QImage并发送
                    image = QImage(rgb_frame.data, w, h, bytes_per_line, QImage.Format_RGB888)
                    self.frame_ready.emit(image)
                    
                    # 适当延时，避免CPU占用过高
                    self.msleep(30)
                except Exception as e:
                    with self._lock:
                        self._error_count += 1
                        error_count = self._error_count
                    logger.error(f"处理摄像头帧时出错 (错误次数: {error_count}): {str(e)}")
                    logger.error(traceback.format_exc())
                    if error_count >= self._max_errors:
                        self.error.emit(f"处理摄像头画面出错: {str(e)}")
                        break
                    continue
        
        except Exception as e:
            logger.error(f"摄像头线程运行错误: {str(e)}")
            logger.error(traceback.format_exc())
            self.error.emit(f"摄像头错误: {str(e)}")
        finally:
            self._cleanup()

    def stop(self):
        """停止摄像头线程"""
        try:
            logger.info("正在停止摄像头线程...")
            self._running = False
            if self.isRunning():
                self.wait(1000)  # 等待最多1秒
                if self.isRunning():
                    logger.warning("摄像头线程未能正常停止，强制终止")
                    self.terminate()
                    self.wait()
            self._cleanup()
            logger.info("摄像头线程已停止")
        except Exception as e:
            logger.error(f"停止摄像头线程时出错: {str(e)}")
            logger.error(traceback.format_exc())

    def _cleanup(self):
        """清理资源"""
        try:
            if self._capture is not None:
                logger.info("正在释放摄像头资源...")
                self._capture.release()
                self._capture = None
            self._running = False
            with self._lock:
                self._error_count = 0
            logger.info("摄像头资源已释放")
        except Exception as e:
            logger.error(f"清理摄像头资源时出错: {str(e)}")
            logger.error(traceback.format_exc())

class LoginWindow(QWidget):
    """
    登录窗口界面
    实现账号密码输入和人脸识别
    """
    def __init__(self, db_config=None):
        try:
            logger.info("开始初始化登录窗口...")
            super().__init__()
            self.initialization_error = False
            self.error_message = ""
            
            # 初始化认证器
            if db_config is None:
                from ..config import DB_CONFIG
                db_config = DB_CONFIG
            logger.info("正在初始化认证器...")
            self.authenticator = Authenticator(db_config)
            logger.info("认证器初始化完成")
            
            # 初始化线程
            self.login_thread = None
            self.face_login_thread = None
            self.camera_thread = None
            self.current_frame = None
            
            # 初始化UI
            logger.info("正在初始化UI...")
            self.init_ui()
            logger.info("UI初始化完成")
            
        except Exception as e:
            self.error_message = f"初始化失败: {str(e)}"
            logger.error(f"{self.error_message}\n{traceback.format_exc()}")
            self.initialization_error = True
            # 创建一个基本的UI，只显示错误信息
            self.init_error_ui()
            # 确保错误消息能够显示
            QTimer.singleShot(100, lambda: self.show_error_message(self.error_message))
    
    def init_ui(self):
        """初始化UI界面"""
        # 设置窗口标题和大小
        self.setWindowTitle('人脸识别登录系统')
        self.resize(800, 500)
        
        # 创建主布局
        main_layout = QHBoxLayout()
        
        # 左侧布局（账号密码输入）
        left_layout = QVBoxLayout()
        
        # 账号输入
        username_layout = QHBoxLayout()
        username_label = QLabel('账号:')
        self.username_input = QLineEdit()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        
        # 密码输入
        password_layout = QHBoxLayout()
        password_label = QLabel('密码:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        
        # 找回密码链接
        forgot_password_layout = QHBoxLayout()
        forgot_password_layout.addStretch()
        self.forgot_password_link = QPushButton("忘记密码?")
        self.forgot_password_link.setFlat(True)
        self.forgot_password_link.setCursor(QCursor(Qt.PointingHandCursor))
        self.forgot_password_link.setStyleSheet("color: blue; text-decoration: underline;")
        self.forgot_password_link.clicked.connect(self.show_forgot_password_dialog)
        forgot_password_layout.addWidget(self.forgot_password_link)
        
        # 按钮布局
        button_layout = QVBoxLayout()
        
        # 登录按钮
        self.login_button = QPushButton('账号密码登录')
        self.login_button.clicked.connect(self.login)
        
        # 人脸登录按钮
        self.face_login_button = QPushButton('人脸识别登录')
        self.face_login_button.clicked.connect(self.start_face_login)
        
        # 注册按钮
        self.register_button = QPushButton('注册新用户')
        self.register_button.clicked.connect(self.open_register_window)
        
        # 开始/停止摄像头按钮
        self.camera_button = QPushButton('开启摄像头')
        self.camera_button.clicked.connect(self.toggle_camera)
        
        # 添加按钮到布局
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.face_login_button)
        button_layout.addWidget(self.camera_button)
        button_layout.addWidget(self.register_button)
        
        # 添加所有控件到左侧布局
        left_layout.addLayout(username_layout)
        left_layout.addLayout(password_layout)
        left_layout.addLayout(forgot_password_layout)
        left_layout.addLayout(button_layout)
        left_layout.addStretch()
        
        # 右侧布局（摄像头预览）
        right_layout = QVBoxLayout()
        
        # 摄像头标签
        self.camera_label = QLabel('摄像头预览')
        self.camera_label.setAlignment(Qt.AlignCenter)
        self.camera_label.setMinimumSize(400, 300)
        self.camera_label.setStyleSheet("border: 1px solid #cccccc;")
        
        # 状态标签
        self.status_label = QLabel('请输入账号密码或直接使用人脸识别登录')
        self.status_label.setAlignment(Qt.AlignCenter)
        
        # 添加控件到右侧布局
        right_layout.addWidget(self.camera_label)
        right_layout.addWidget(self.status_label)
        
        # 将左右布局添加到主布局
        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 2)
        
        # 设置主布局
        self.setLayout(main_layout)
    
    def toggle_camera(self):
        """切换摄像头状态"""
        try:
            if not hasattr(self, 'camera_thread') or self.camera_thread is None:
                logger.info("正在创建摄像头线程...")
                # 创建并启动摄像头线程
                self.camera_thread = CameraThread()
                self.camera_thread.frame_ready.connect(self.update_frame)
                self.camera_thread.error.connect(self.handle_camera_error)
                self.camera_thread.started.connect(self.handle_camera_started)
                
                # 禁用按钮，显示加载状态
                self.camera_button.setEnabled(False)
                self.camera_label.setText("正在启动摄像头...")
                
                # 启动线程
                self.camera_thread.start()
                logger.info("摄像头线程已启动")
            else:
                # 停止摄像头线程
                if self.camera_thread._running:
                    logger.info("正在关闭摄像头...")
                    self.camera_thread.stop()
                    self.camera_thread = None
                    self.camera_button.setText('开启摄像头')
                    self.status_label.setText('请选择登录方式')
                    
                    # 清除摄像头预览
                    try:
                        if hasattr(self, 'camera_label') and self.camera_label is not None and not sip.isdeleted(self.camera_label):
                            # 创建一个空白图像
                            blank_image = QPixmap(640, 480)
                            blank_image.fill(QColor(0, 0, 0))
                            self.camera_label.setPixmap(blank_image)
                            self.camera_label.setText('摄像头已关闭')
                            logger.info("摄像头预览已清除")
                    except Exception as e:
                        logger.error(f"清除摄像头预览时出错: {str(e)}")
                        logger.error(traceback.format_exc())
        except Exception as e:
            logger.error(f"切换摄像头状态时出错: {str(e)}")
            logger.error(traceback.format_exc())
            self.handle_camera_error(f"切换摄像头失败: {str(e)}")

    def handle_camera_started(self):
        """处理摄像头启动成功"""
        try:
            logger.info("摄像头已成功启动")
            self.camera_button.setEnabled(True)
            self.camera_button.setText('关闭摄像头')
            self.camera_label.setText('等待摄像头画面...')
        except Exception as e:
            logger.error(f"处理摄像头启动事件时出错: {str(e)}")
            logger.error(traceback.format_exc())

    def handle_camera_error(self, error_msg):
        """处理摄像头错误"""
        try:
            logger.error(f"摄像头错误: {error_msg}")
            if hasattr(self, 'camera_thread') and self.camera_thread:
                self.camera_thread.stop()
                self.camera_thread = None
            self.camera_button.setEnabled(True)
            self.camera_button.setText('开启摄像头')
            self.camera_label.setText(f'摄像头错误: {error_msg}')
            QMessageBox.warning(self, '摄像头错误', error_msg)
        except Exception as e:
            logger.error(f"处理摄像头错误时出错: {str(e)}")
            logger.error(traceback.format_exc())

    def update_frame(self, image):
        """更新摄像头画面"""
        try:
            if image is None or image.isNull():
                logger.warning("收到空的图像数据")
                return
                
            # 调整图像大小以适应标签
            scaled_image = image.scaled(self.camera_label.size(), 
                                     Qt.KeepAspectRatio,
                                     Qt.SmoothTransformation)
            
            # 将QImage转换为QPixmap并显示
            self.camera_label.setPixmap(QPixmap.fromImage(scaled_image))
            
            # 保存当前帧用于人脸识别
            self.current_frame = image
            
            try:
                # 将QImage转换为numpy数组
                width = image.width()
                height = image.height()
                
                # 确保图像格式正确
                if image.format() != QImage.Format_RGB32:
                    logger.debug(f"转换图像格式从 {image.format()} 到 Format_RGB32")
                    image = image.convertToFormat(QImage.Format_RGB32)
                
                # 获取图像数据
                ptr = image.constBits()
                ptr.setsize(height * width * 4)
                arr = np.frombuffer(ptr, np.uint8).reshape((height, width, 4))
                
                # 转换为BGR格式
                self.current_frame_bgr = cv2.cvtColor(arr, cv2.COLOR_RGBA2BGR)
                logger.debug("图像格式转换成功")
                
            except Exception as e:
                logger.error(f"图像格式转换失败: {str(e)}")
                logger.error(traceback.format_exc())
                self.current_frame = None
                self.current_frame_bgr = None
                # 不要在这里显示错误消息，因为这个方法会被频繁调用
                # 而是在尝试使用图像时（如人脸识别）再显示错误
            
        except Exception as e:
            logger.error(f"更新摄像头画面失败: {str(e)}")
            logger.error(traceback.format_exc())
            self.current_frame = None
            self.current_frame_bgr = None
    
    def register_user(self):
        """注册新用户"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, '错误', '账号和密码不能为空')
            return
        
        # 保存当前摄像头状态
        camera_was_active = self.camera_thread and self.camera_thread._running
        
        if camera_was_active:
            # 暂停摄像头预览但不释放摄像头
            self.camera_thread.stop()
        
        # 显示注册对话框
        dialog = RegisterDialog(self, username, password, self.authenticator)
        result = dialog.exec_()
        
        # 恢复摄像头预览
        if camera_was_active:
            self.camera_thread.start()
    
    def register_face(self):
        """注册人脸"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            MessageBox.warning(self, '错误', '请输入账号和密码')
            return
        
        # 验证账号密码
        if not self.authenticator.db.verify_password(username, password):
            MessageBox.warning(self, '错误', '账号或密码错误')
            return
        
        # 检查摄像头是否开启
        if not self.camera_thread or not self.camera_thread._running:
            MessageBox.warning(self, '错误', '请先开启摄像头')
            return
        
        # 获取当前帧并验证
        if not hasattr(self, 'current_frame_bgr') or self.current_frame_bgr is None:
            MessageBox.warning(self, '提示', '无法获取摄像头画面，请确保摄像头正常工作')
            return
            
        # 检查人脸质量
        is_valid, error_message = check_face_quality(self.current_frame_bgr)
        if not is_valid:
            MessageBox.warning(self, '提示', error_message)
            return
        
        # 更新状态
        self.status_label.setText('正在注册人脸，请稍候...')
        self.face_login_button.setEnabled(False)
        QApplication.processEvents()
        
        try:
            # 注册人脸
            success = self.authenticator.register_face(username, self.current_frame_bgr)
            
            # 显示结果
            if success:
                MessageBox.info(self, '成功', f'用户 {username} 人脸注册成功！现在可以使用人脸识别登录了。')
                self.status_label.setText('人脸注册成功，可以使用人脸识别登录')
            else:
                MessageBox.warning(self, '错误', '人脸注册失败，请重试')
                self.status_label.setText('人脸注册失败，请重试')
        except Exception as e:
            logger.error(f"人脸注册过程出错: {str(e)}\n{traceback.format_exc()}")
            MessageBox.error(self, '系统错误', f'人脸注册过程出错: {str(e)}')
            self.status_label.setText('人脸注册失败，请重试')
        finally:
            # 恢复UI状态
            self.face_login_button.setEnabled(True)
    
    def login(self):
        """账号密码登录"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            MessageBox.warning(self, '错误', '请输入用户名和密码')
            return
        
        # 禁用登录按钮
        self.login_button.setEnabled(False)
        self.status_label.setText('正在登录...')
        
        # 创建并启动登录线程
        self.login_thread = LoginThread(self.authenticator, username, password)
        self.login_thread.finished.connect(self.on_login_finished)
        self.login_thread.start()
    
    def on_login_finished(self, success, message):
        """登录完成回调"""
        try:
            # 恢复登录按钮
            self.login_button.setEnabled(True)
            
            if success:
                # 获取当前用户信息（包括角色）
                user_info = self.authenticator.get_current_user()
                logger.info(f"账号密码登录成功，用户信息: {user_info}")
                
                if not user_info:
                    logger.warning("登录成功但无法获取用户信息，按普通用户处理")
                    self.on_login_success(message)
                    return
                    
                # 根据角色判断登录流程
                try:
                    role = user_info.get('role', 0)
                    if isinstance(role, str):
                        role = int(role)
                        
                    if role >= UserRole.ADMIN.value:
                        logger.info(f"用户 {message} 是管理员，角色值: {role}")
                        self.on_admin_login_success(message)
                    else:
                        logger.info(f"用户 {message} 是普通用户，角色值: {role}")
                        self.on_login_success(message)
                except (ValueError, TypeError) as e:
                    logger.error(f"判断用户角色时出错: {str(e)}，按普通用户处理")
                    self.on_login_success(message)
            else:
                logger.warning(f"登录失败: {message}")
                MessageBox.warning(self, '登录失败', message)
                self.status_label.setText('登录失败，请重试')
        except Exception as e:
            logger.error(f"处理登录结果时出错: {str(e)}\n{traceback.format_exc()}")
            MessageBox.error(self, '系统错误', f"处理登录结果时出错: {str(e)}")
            self.status_label.setText('登录失败，请重试')
    
    def start_face_login(self):
        """开始人脸登录流程"""
        try:
            logger.info("开始人脸登录流程...")
            
            # 检查摄像头状态
            if not hasattr(self, 'camera_thread') or self.camera_thread is None or not hasattr(self.camera_thread, '_running') or not self.camera_thread._running:
                logger.warning("摄像头未开启")
                MessageBox.warning(self, '提示', '请先开启摄像头')
                return
            
            # 获取当前帧并验证
            if not hasattr(self, 'current_frame_bgr') or self.current_frame_bgr is None:
                logger.warning("无法获取摄像头画面")
                MessageBox.warning(self, '提示', '无法获取摄像头画面，请确保摄像头正常工作')
                return
            
            # 检查人脸质量
            is_valid, error_message = check_face_quality(self.current_frame_bgr)
            if not is_valid:
                logger.warning(f"人脸质量检查失败: {error_message}")
                MessageBox.warning(self, '提示', error_message)
                return
            
            # 禁用登录按钮，显示加载状态
            self.face_login_button.setEnabled(False)
            self.status_label.setText('正在进行人脸识别...')
            
            try:
                # 检查人脸检测器是否已被释放
                if (hasattr(self.authenticator, 'face_detector') and 
                    (self.authenticator.face_detector is None or 
                     hasattr(self.authenticator.face_detector, 'mtcnn') and 
                     self.authenticator.face_detector.mtcnn is None)):
                    logger.warning("人脸检测器已被释放，尝试重新初始化...")
                    
                    # 如果人脸检测器为None，重新创建
                    if self.authenticator.face_detector is None:
                        from ..detection.face_detector import FaceDetector
                        self.authenticator.face_detector = FaceDetector()
                        logger.info("人脸检测器重新创建成功")
                    # 如果只是mtcnn为None，调用重新初始化方法
                    elif hasattr(self.authenticator.face_detector, 'reinitialize'):
                        if not self.authenticator.face_detector.reinitialize():
                            raise RuntimeError("人脸检测器重新初始化失败")
                        logger.info("人脸检测器重新初始化成功")
                
                # 创建并启动人脸登录线程
                self.face_login_thread = FaceLoginThread(self.authenticator, self.current_frame_bgr)
                self.face_login_thread.finished.connect(self.on_face_login_finished)
                self.face_login_thread.start()
                
            except Exception as e:
                error_msg = f"启动人脸识别线程失败: {str(e)}"
                logger.error(f"{error_msg}\n{traceback.format_exc()}")
                MessageBox.error(self, '系统提示', '人脸识别启动失败，请重试')
                # 恢复UI状态
                self.face_login_button.setEnabled(True)
                self.status_label.setText('请选择登录方式')
            
        except Exception as e:
            error_msg = f"人脸登录过程出错: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            MessageBox.error(self, '系统提示', '人脸识别过程出现错误，请重试')
            # 恢复UI状态
            self.face_login_button.setEnabled(True)
            self.status_label.setText('请选择登录方式')
    
    def on_face_login_finished(self, success, message):
        """处理人脸登录线程完成的结果"""
        try:
            logger.info(f"收到人脸登录结果: success={success}, message={message}")
            
            if success:
                logger.info(f"人脸识别成功，用户名: {message}")
                # 先使用用户名登录，设置当前用户信息
                login_result = self.authenticator.login(message, None)
                if not login_result['success']:
                    logger.error(f"人脸识别后登录失败: {login_result['message']}")
                    MessageBox.error(self, "登录失败", f"人脸识别成功，但登录失败: {login_result['message']}")
                    return
                
                # 获取用户角色并判断
                user_info = self.authenticator.get_current_user()
                logger.info(f"人脸登录用户信息: {user_info}")
                
                if user_info and user_info.get('role', 0) >= UserRole.ADMIN.value:
                    self.on_admin_login_success(message)
                else:
                    self.on_login_success(message)
            else:
                logger.warning(f"人脸识别失败: {message}")
                logger.info("准备显示错误弹窗...")
                
                # 确保窗口保持显示状态
                self.setVisible(True)
                self.activateWindow()
                self.raise_()
                logger.info("窗口已设置为可见状态")
                
                # 显示错误信息对话框
                try:
                    logger.info("正在创建MessageBox...")
                    MessageBox.warning(
                        self,
                        "人脸识别失败",
                        message
                    )
                    logger.info("MessageBox显示完成")
                except Exception as e:
                    logger.error(f"显示MessageBox时出错: {str(e)}")
                    logger.error(traceback.format_exc())
                
                # 更新状态标签
                self.status_label.setText('人脸识别失败，请重试')
                logger.info("状态标签已更新")
        except Exception as e:
            error_msg = f"处理人脸登录结果时出错: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            
            # 确保窗口保持显示状态
            self.setVisible(True)
            self.activateWindow()
            self.raise_()
            
            # 显示错误信息
            try:
                MessageBox.error(self, "错误", error_msg)
            except Exception as msg_error:
                logger.error(f"显示错误MessageBox时出错: {str(msg_error)}")
        finally:
            # 恢复UI状态
            self.face_login_button.setEnabled(True)
            if not success:  # 只在失败时更新状态文本
                self.status_label.setText('请选择登录方式')
            # 清理线程
            if hasattr(self, 'face_login_thread') and self.face_login_thread is not None:
                try:
                    self.face_login_thread.quit()
                    self.face_login_thread.wait()
                except Exception as e:
                    logger.error(f"清理人脸登录线程时出错: {str(e)}")
                finally:
                    self.face_login_thread = None
            logger.info("人脸登录处理完成")
    
    def show_forgot_password_dialog(self):
        """显示找回密码对话框"""
        dialog = ForgotPasswordDialog(self, self.authenticator)
        dialog.exec_()
    
    def reset_ui_state(self):
        """重置UI状态"""
        try:
            # 停止所有线程
            threads_to_stop = [
                ('login_thread', '登录'),
                ('face_login_thread', '人脸登录'),
                ('camera_thread', '摄像头')
            ]
            
            for thread_attr, thread_name in threads_to_stop:
                if hasattr(self, thread_attr):
                    thread = getattr(self, thread_attr)
                    if thread is not None:
                        try:
                            logger.info(f"正在停止{thread_name}线程...")
                            if isinstance(thread, CameraThread):
                                thread.stop()  # 摄像头线程有特殊的停止方法
                            else:
                                if thread.isRunning():
                                    thread.quit()
                                    if not thread.wait(1000):  # 等待最多1秒
                                        thread.terminate()
                                        thread.wait()
                            
                            # 清理线程对象
                            setattr(self, thread_attr, None)
                            logger.info(f"{thread_name}线程已停止")
                        except Exception as e:
                            logger.error(f"停止{thread_name}线程时出错: {str(e)}")
            
            # 重置UI组件状态
            ui_components = {
                'camera_label': ('setText', ['摄像头已关闭']),
                'camera_button': [
                    ('setText', ['开启摄像头']),
                    ('setEnabled', [True])
                ],
                'login_button': ('setEnabled', [True]),
                'face_login_button': ('setEnabled', [True]),
                'register_button': ('setEnabled', [True]),
                'username_input': [
                    ('clear', []),
                    ('setEnabled', [True])
                ],
                'password_input': [
                    ('clear', []),
                    ('setEnabled', [True])
                ]
            }
            
            for component_name, actions in ui_components.items():
                try:
                    if hasattr(self, component_name):
                        component = getattr(self, component_name)
                        if component is not None and not self.isHidden() and not sip.isdeleted(component):
                            if not isinstance(actions, list):
                                actions = [actions]
                            for action in actions:
                                try:
                                    method_name, args = action
                                    if hasattr(component, method_name):
                                        method = getattr(component, method_name)
                                        method(*args)
                                except Exception as e:
                                    logger.error(f"设置组件 {component_name} 状态时出错: {str(e)}")
                except Exception as e:
                    logger.error(f"处理组件 {component_name} 时出错: {str(e)}")
            
            # 清除当前帧
            self.current_frame = None
            self.current_frame_bgr = None
            
            # 清除摄像头预览图像
            try:
                if hasattr(self, 'camera_label') and self.camera_label is not None and not sip.isdeleted(self.camera_label):
                    # 创建一个空白图像
                    blank_image = QPixmap(640, 480)
                    blank_image.fill(QColor(0, 0, 0))
                    self.camera_label.setPixmap(blank_image)
                    self.camera_label.setText('摄像头已关闭')
                    logger.info("摄像头预览已清除")
            except Exception as e:
                logger.error(f"清除摄像头预览时出错: {str(e)}")
            
            # 清理认证器资源
            if hasattr(self, 'authenticator') and self.authenticator is not None:
                try:
                    if hasattr(self.authenticator, 'face_detector') and self.authenticator.face_detector is not None:
                        self.authenticator.face_detector.release()
                        
                        # 重新初始化人脸检测器
                        if hasattr(self.authenticator.face_detector, 'reinitialize'):
                            self.authenticator.face_detector.reinitialize()
                except Exception as e:
                    logger.error(f"清理认证器资源时出错: {str(e)}")
            
        except Exception as e:
            logger.error(f"重置UI状态时出错: {str(e)}\n{traceback.format_exc()}")

    def on_admin_login_success(self, username):
        """管理员登录成功的处理"""
        try:
            # 获取用户信息并确保用户具有管理员权限
            user_info = self.authenticator.get_current_user()
            logger.info(f"管理员登录用户信息: {user_info}")
            
            # 检查是否存在用户信息
            if not user_info:
                logger.error("获取用户信息失败，将作为普通用户登录")
                self.on_login_success(username)
                return
                
            # 获取用户角色并确保是整数类型
            try:
                role = user_info.get('role', 0)
                if isinstance(role, str):
                    role = int(role)
                
                # 检查管理员权限
                if role < UserRole.ADMIN.value:
                    logger.warning(f"用户 {username} 不是管理员 (角色值: {role})，作为普通用户登录")
                    self.on_login_success(username)
                    return
            except (ValueError, TypeError) as e:
                logger.error(f"处理用户角色时出错: {str(e)}，将作为普通用户登录")
                self.on_login_success(username)
                return
            
            # 询问是否进入管理后台
            reply = MessageBox.question(
                self,
                "登录成功",
                "是否进入管理后台？\n选择\"否\"将以普通用户身份登录。",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                # 导入管理后台窗口
                from .admin_window import AdminWindow
                
                try:
                    # 创建并显示管理后台窗口
                    self.admin_window = AdminWindow(self.authenticator)
                    self.admin_window.logout_signal.connect(self.handle_logout)
                    self.admin_window.show()
                    
                    # 隐藏登录窗口
                    self.hide()
                except Exception as e:
                    logger.error(f"创建管理后台窗口时出错: {str(e)}")
                    logger.error(traceback.format_exc())
                    MessageBox.error(self, "错误", f"无法打开管理后台: {str(e)}")
                    # 回退到普通用户登录
                    self.on_login_success(username)
            else:
                # 进入普通用户界面
                self.on_login_success(username)
            
            # 清理资源
            if hasattr(self, 'camera_thread') and self.camera_thread:
                self.camera_thread.stop()
                self.camera_thread = None
            
            logger.info(f"管理员 {username} 登录成功")
            
        except Exception as e:
            logger.error(f"处理管理员登录成功时出错: {str(e)}")
            logger.error(traceback.format_exc())
            MessageBox.error(self, "错误", f"登录成功处理时出错: {str(e)}")
            # 重置状态
            self.reset_ui_state()
            self.show()

    def on_login_success(self, username):
        """登录成功的处理"""
        try:
            # 保存当前用户名
            self.current_username = username
            
            # 延迟导入 MainWindow 类，避免循环导入问题
            from .main_window import MainWindow
            
            # 创建并显示主窗口
            self.main_window = MainWindow(username, self.authenticator)
            self.main_window.logout_signal.connect(self.handle_logout)
            self.main_window.show()
            
            # 隐藏登录窗口
            self.hide()
            
            # 清理资源
            if hasattr(self, 'camera_thread') and self.camera_thread:
                self.camera_thread.stop()
                self.camera_thread = None
            
            logger.info(f"用户 {username} 登录成功")
            
        except Exception as e:
            logger.error(f"处理登录成功时出错: {str(e)}")
            logger.error(traceback.format_exc())
            MessageBox.error(self, "错误", f"登录成功处理时出错: {str(e)}")
            # 重置状态
            self.reset_ui_state()
            self.show()

    def handle_logout(self):
        """处理登出信号"""
        try:
            logger.info("收到登出信号，正在处理...")
            
            # 重置UI状态
            self.reset_ui_state()
            
            # 关闭主窗口（不需要再次确认）
            if hasattr(self, 'main_window') and self.main_window is not None:
                logger.info("正在关闭主窗口...")
                try:
                    self.main_window.close()
                    self.main_window.deleteLater()  # 确保窗口被正确删除
                except Exception as e:
                    logger.error(f"关闭主窗口时出错: {str(e)}")
                finally:
                    self.main_window = None
                logger.info("主窗口已关闭")
                
            # 关闭管理员窗口（如果存在）
            if hasattr(self, 'admin_window') and self.admin_window is not None:
                logger.info("正在关闭管理后台窗口...")
                try:
                    self.admin_window.close()
                    self.admin_window.deleteLater()
                except Exception as e:
                    logger.error(f"关闭管理后台窗口时出错: {str(e)}")
                finally:
                    self.admin_window = None
                logger.info("管理后台窗口已关闭")

            # 立即清除摄像头预览
            try:
                if hasattr(self, 'camera_label') and self.camera_label is not None and not sip.isdeleted(self.camera_label):
                    # 创建一个空白图像
                    blank_image = QPixmap(640, 480)
                    blank_image.fill(QColor(0, 0, 0))
                    self.camera_label.setPixmap(blank_image)
                    self.camera_label.setText('摄像头已关闭')
                    logger.info("摄像头预览已立即清除")
            except Exception as e:
                logger.error(f"清除摄像头预览时出错: {str(e)}")
                logger.error(traceback.format_exc())

            # 重新初始化认证器
            try:
                logger.info("正在重新初始化认证器...")
                if hasattr(self, 'authenticator') and self.authenticator is not None:
                    self.authenticator.close()
                from ..config import DB_CONFIG
                self.authenticator = Authenticator(DB_CONFIG)
                logger.info("认证器重新初始化完成")
            except Exception as e:
                logger.error(f"重新初始化认证器时出错: {str(e)}\n{traceback.format_exc()}")
                MessageBox.error(self, "错误", "重新初始化认证器失败，请重启应用")
                self.close()
                return
            
            # 先显示登录窗口
            self.show()
            logger.info("登出处理完成")
            
        except Exception as e:
            logger.error(f"处理登出时出错: {str(e)}\n{traceback.format_exc()}")
            MessageBox.error(self, "错误", f"登出时出错: {str(e)}")
            # 尝试恢复到登录状态
            self.show()

    def showEvent(self, event):
        """窗口显示事件"""
        try:
            logger.info("登录窗口显示事件触发")
            super().showEvent(event)
            logger.info("登录窗口显示")
            
            # 确保摄像头按钮可用
            if hasattr(self, 'camera_button'):
                self.camera_button.setEnabled(True)
                self.camera_button.setText('开启摄像头')
            
            # 确保摄像头已关闭
            if hasattr(self, 'camera_thread') and self.camera_thread:
                logger.info("正在关闭遗留的摄像头...")
                self.camera_thread.stop()
                self.camera_thread = None
                if hasattr(self, 'camera_label'):
                    self.camera_label.setText('摄像头已关闭')
                logger.info("遗留的摄像头已关闭")
        except Exception as e:
            logger.error(f"处理窗口显示事件时出错: {str(e)}\n{traceback.format_exc()}")
    
    def hideEvent(self, event):
        """窗口隐藏事件"""
        try:
            logger.info("登录窗口隐藏事件触发")
            super().hideEvent(event)
            logger.info("登录窗口隐藏")
            
            # 确保摄像头已关闭
            if hasattr(self, 'camera_thread') and self.camera_thread:
                logger.info("正在关闭摄像头...")
                self.camera_thread.stop()
                self.camera_thread = None
                logger.info("摄像头已关闭")
        except Exception as e:
            logger.error(f"处理窗口隐藏事件时出错: {str(e)}\n{traceback.format_exc()}")
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        try:
            logger.info("登录窗口关闭事件触发")
            # 确保所有资源被释放
            self.reset_ui_state()
            if hasattr(self, 'authenticator'):
                self.authenticator.close()
            super().closeEvent(event)
            logger.info("登录窗口已关闭")
        except Exception as e:
            logger.error(f"处理窗口关闭事件时出错: {str(e)}\n{traceback.format_exc()}")
            event.accept()  # 确保窗口能够关闭

    def open_register_window(self):
        """打开注册窗口"""
        try:
            from .register_window import RegisterWindow
            from ..config import DB_CONFIG
            from ..utils.logger import logger
            
            logger.info("正在创建注册窗口...")
            
            # 如果已经存在注册窗口，先关闭它
            if hasattr(self, 'register_window') and self.register_window:
                try:
                    self.register_window.close()
                    self.register_window = None
                except:
                    pass
            
            # 暂时禁用注册按钮防止重复点击
            self.register_button.setEnabled(False)
            
            # 创建新的注册窗口
            self.register_window = RegisterWindow(DB_CONFIG, None)  # 设置为无父窗口
            
            # 连接窗口关闭信号
            self.register_window.destroyed.connect(self.on_register_window_closed)
            
            logger.info("注册窗口创建完成，准备显示")
            self.register_window.show()
            logger.info("注册窗口已显示")
            
        except Exception as e:
            from ..utils.logger import logger
            error_msg = f"无法打开注册窗口: {str(e)}"
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            MessageBox.warning(self, '错误', error_msg)
        finally:
            # 重新启用注册按钮
            self.register_button.setEnabled(True)
    
    def on_register_window_closed(self):
        """注册窗口关闭时的处理"""
        logger.info("注册窗口已关闭")
        # 清除引用
        self.register_window = None
        # 确保登录窗口可用
        self.setEnabled(True)
        self.activateWindow()

    def init_error_ui(self):
        """初始化错误UI"""
        # 创建主布局
        main_layout = QVBoxLayout()
        
        # 错误信息标签
        self.error_label = QLabel(self.error_message)
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setStyleSheet("color: red;")
        
        # 关闭按钮
        self.close_button = QPushButton("关闭")
        self.close_button.clicked.connect(self.close)
        
        # 添加控件到布局
        main_layout.addWidget(self.error_label)
        main_layout.addWidget(self.close_button)
        
        # 设置主布局
        self.setLayout(main_layout)

    def show_error_message(self, message):
        """显示错误消息"""
        try:
            logger.warning(f"显示错误消息: {message}")
            # 使用自定义的MessageBox类显示错误消息
            MessageBox.warning(
                self,
                "提示",
                message,
                buttons=QMessageBox.Ok,
                default_button=QMessageBox.Ok
            )
        except Exception as e:
            logger.error(f"显示错误消息失败: {str(e)}")
            logger.error(traceback.format_exc())

    def __del__(self):
        """析构函数"""
        try:
            # 停止所有线程，释放所有资源
            if hasattr(self, 'reset_ui_state'):
                try:
                    self.reset_ui_state()
                except Exception:
                    pass
                    
            # 关闭认证器
            if hasattr(self, 'authenticator') and self.authenticator is not None:
                try:
                    self.authenticator.close()
                except Exception:
                    pass
                
            # 不要使用日志记录器，因为它可能已被清理
        except Exception:
            # 析构函数中的异常不应该传播
            pass


class RegisterDialog(QDialog):
    """注册对话框"""
    
    def __init__(self, parent, username, password, authenticator):
        super().__init__(parent)
        
        self.username = username
        self.password = password
        self.authenticator = authenticator
        
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("完善注册信息")
        self.setMinimumWidth(350)
        
        # 创建表单布局
        layout = QFormLayout(self)
        
        # 用户名（只读）
        self.username_edit = QLineEdit(self.username)
        self.username_edit.setReadOnly(True)
        layout.addRow("用户名:", self.username_edit)
        
        # 电子邮件
        self.email_edit = QLineEdit()
        layout.addRow("电子邮件:", self.email_edit)
        
        # 手机号码
        self.phone_edit = QLineEdit()
        layout.addRow("手机号码:", self.phone_edit)
        
        # 姓名
        self.full_name_edit = QLineEdit()
        layout.addRow("姓名:", self.full_name_edit)
        
        # 按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.register)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def register(self):
        """注册用户"""
        # 获取表单数据
        email = self.email_edit.text().strip()
        phone = self.phone_edit.text().strip()
        full_name = self.full_name_edit.text().strip()
        
        logger.info(f"正在注册用户: {self.username}, 邮箱: {email}, 手机: {phone}")
        
        # 验证表单数据
        valid, message = validate_register_form(self.username, self.password, self.password, email, phone)
        if not valid:
            logger.warning(f"用户 {self.username} 注册表单验证失败: {message}")
            MessageBox.warning(self, "警告", f"表单验证失败: {message}")
            return
        
        # 注册用户
        if self.authenticator.register_user(self.username, self.password, email, phone, full_name):
            logger.info(f"用户 {self.username} 注册成功")
            MessageBox.info(self, "成功", f"用户 {self.username} 注册成功！\n请继续注册人脸")
            self.accept()
        else:
            logger.warning(f"用户 {self.username} 注册失败，用户名可能已存在")
            MessageBox.error(self, "错误", "注册失败，用户名可能已存在")


class ForgotPasswordDialog(QDialog):
    """找回密码对话框"""
    
    def __init__(self, parent, authenticator):
        super().__init__(parent)
        
        self.authenticator = authenticator
        self.reset_token = None
        
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("找回密码")
        self.setMinimumWidth(350)
        
        # 创建主布局
        self.main_layout = QVBoxLayout(self)
        
        # 创建步骤1的布局（请求重置）
        self.step1_widget = QWidget()
        step1_layout = QFormLayout(self.step1_widget)
        
        # 用户名或邮箱输入
        self.username_email_edit = QLineEdit()
        step1_layout.addRow("用户名或邮箱:", self.username_email_edit)
        
        # 请求重置按钮
        self.request_button = QPushButton("发送重置链接")
        self.request_button.clicked.connect(self.request_reset)
        step1_layout.addWidget(self.request_button)
        
        # 创建步骤2的布局（重置密码）
        self.step2_widget = QWidget()
        step2_layout = QFormLayout(self.step2_widget)
        
        # 重置令牌输入
        self.token_edit = QLineEdit()
        step2_layout.addRow("重置令牌:", self.token_edit)
        
        # 新密码输入
        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.Password)
        step2_layout.addRow("新密码:", self.new_password_edit)
        
        # 确认新密码输入
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        step2_layout.addRow("确认新密码:", self.confirm_password_edit)
        
        # 重置密码按钮
        self.reset_button = QPushButton("重置密码")
        self.reset_button.clicked.connect(self.reset_password)
        step2_layout.addWidget(self.reset_button)
        
        # 添加步骤1到主布局
        self.main_layout.addWidget(self.step1_widget)
        
        # 步骤2初始隐藏
        self.step2_widget.hide()
        self.main_layout.addWidget(self.step2_widget)
        
        # 关闭按钮
        self.close_button = QPushButton("关闭")
        self.close_button.clicked.connect(self.reject)
        self.main_layout.addWidget(self.close_button)
    
    def request_reset(self):
        """请求重置密码"""
        username_email = self.username_email_edit.text().strip()
        
        if not username_email:
            MessageBox.warning(self, "警告", "请输入用户名或邮箱")
            return
        
        # 验证邮箱格式（如果输入的是邮箱）
        if '@' in username_email:
            valid, message = validate_email(username_email)
            if not valid:
                MessageBox.warning(self, "警告", message)
                return
        
        # 生成重置令牌
        success, result = self.authenticator.initiate_password_reset(username_email)
        
        if success:
            self.reset_token = result
            # 显示令牌（在实际应用中，应该通过邮件发送）
            MessageBox.info(
                self, 
                "成功", 
                f"重置令牌已生成，请查看您的邮箱。\n\n"
                f"注意：在实际应用中，此令牌应通过邮件发送，而不是直接显示。\n\n"
                f"为了演示目的，您的重置令牌是：\n{result}"
            )
            
            # 切换到步骤2
            self.step1_widget.hide()
            self.token_edit.setText(result)  # 自动填充令牌（仅用于演示）
            self.step2_widget.show()
        else:
            MessageBox.error(self, "错误", result)
    
    def reset_password(self):
        """重置密码"""
        token = self.token_edit.text().strip()
        new_password = self.new_password_edit.text()
        confirm_password = self.confirm_password_edit.text()
        
        # 验证输入
        if not token or not new_password or not confirm_password:
            MessageBox.warning(self, "警告", "请填写所有字段")
            return
        
        if new_password != confirm_password:
            MessageBox.warning(self, "警告", "两次输入的密码不一致")
            return
        
        if len(new_password) < 6:
            MessageBox.warning(self, "警告", "密码长度不能少于6位")
            return
        
        # 重置密码
        success, message = self.authenticator.reset_password(token, new_password)
        
        if success:
            MessageBox.info(self, "成功", message)
            self.accept()
        else:
            MessageBox.error(self, "错误", message) 