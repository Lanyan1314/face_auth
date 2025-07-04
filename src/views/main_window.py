#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
主窗口
登录成功后显示
"""

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QAction, QMenu, QMenuBar,
                             QDialog, QFormLayout, QLineEdit, QGroupBox,
                             QDialogButtonBox, QTabWidget, QGridLayout, QMessageBox)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
import traceback

from ..utils.logger import get_logger
from .components.message_box import MessageBox
from ..auth.authenticator import Authenticator

logger = get_logger('main_window')


class MainWindow(QMainWindow):
    """主窗口"""
    logout_signal = pyqtSignal()

    def __init__(self, username, authenticator=None):
        """
        初始化主窗口
        :param username: 用户名
        :param authenticator: 认证器实例
        """
        try:
            logger.info(f"开始初始化主窗口 (用户: {username})...")
            super().__init__()

            self.username = username
            self.authenticator = authenticator or Authenticator()

            # 获取完整的用户资料
            self.user_profile = self.authenticator.get_user_profile(username)

            # 初始化UI
            logger.info("正在初始化主窗口UI...")
            self.init_ui()
            logger.info("主窗口UI初始化完成")

        except Exception as e:
            logger.error(f"主窗口初始化失败: {str(e)}\n{traceback.format_exc()}")
            raise

        logger.info(f"主窗口已创建，用户: {username}")

    def init_ui(self):
        """初始化UI"""
        # 设置窗口标题和大小
        self.setWindowTitle('人脸识别登录系统 - 主页')
        self.resize(800, 600)

        # 创建菜单栏
        self.create_menu_bar()

        # 创建中央窗口
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 创建主布局
        main_layout = QVBoxLayout(central_widget)

        # 创建欢迎标签
        welcome_label = QLabel(f"欢迎, {self.username}!")
        welcome_label.setAlignment(Qt.AlignCenter)
        welcome_label.setFont(QFont('Arial', 20))
        main_layout.addWidget(welcome_label)

        # 创建状态标签
        status_label = QLabel("您已成功登录系统")
        status_label.setAlignment(Qt.AlignCenter)
        status_label.setFont(QFont('Arial', 12))
        main_layout.addWidget(status_label)

        # 创建功能区
        self.create_function_area(main_layout)

        # 创建按钮布局
        button_layout = QHBoxLayout()

        # 创建退出按钮
        logout_button = QPushButton("退出登录")
        logout_button.clicked.connect(self.logout)
        button_layout.addWidget(logout_button)

        # 添加按钮布局到主布局
        main_layout.addLayout(button_layout)

    def create_function_area(self, parent_layout):
        """创建功能区"""
        # 创建功能区组
        function_group = QGroupBox("账户管理")
        function_layout = QGridLayout()

        # 个人资料按钮
        profile_btn = QPushButton("个人资料")
        profile_btn.clicked.connect(self.show_profile_dialog)
        function_layout.addWidget(profile_btn, 0, 0)

        # 修改密码按钮
        change_pwd_btn = QPushButton("修改密码")
        change_pwd_btn.clicked.connect(self.show_change_password_dialog)
        function_layout.addWidget(change_pwd_btn, 0, 1)

        # 注销账户按钮
        deactivate_btn = QPushButton("注销账户")
        deactivate_btn.clicked.connect(self.show_deactivate_account_dialog)
        function_layout.addWidget(deactivate_btn, 0, 2)

        # 重新录入人脸按钮
        reface_btn = QPushButton("重新录入人脸")
        reface_btn.clicked.connect(self.show_reface_dialog)
        function_layout.addWidget(reface_btn, 1, 0)

        function_group.setLayout(function_layout)
        parent_layout.addWidget(function_group)

    def create_menu_bar(self):
        """创建菜单栏"""
        # 创建菜单栏
        menu_bar = self.menuBar()

        # 文件菜单
        file_menu = menu_bar.addMenu('文件')

        # 退出动作
        exit_action = QAction('退出', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # 账户菜单
        account_menu = menu_bar.addMenu('账户')

        # 个人资料动作
        profile_action = QAction('个人资料', self)
        profile_action.triggered.connect(self.show_profile_dialog)
        account_menu.addAction(profile_action)

        # 修改密码动作
        change_pwd_action = QAction('修改密码', self)
        change_pwd_action.triggered.connect(self.show_change_password_dialog)
        account_menu.addAction(change_pwd_action)

        # 注销账户动作
        deactivate_action = QAction('注销账户', self)
        deactivate_action.triggered.connect(self.show_deactivate_account_dialog)
        account_menu.addAction(deactivate_action)

        # 帮助菜单
        help_menu = menu_bar.addMenu('帮助')

        # 关于动作
        about_action = QAction('关于', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_profile_dialog(self):
        """显示个人资料对话框"""
        dialog = ProfileDialog(self, self.user_profile, self.authenticator)
        if dialog.exec_() == QDialog.Accepted:
            # 更新用户资料
            self.user_profile = self.authenticator.get_user_profile(self.username)
            MessageBox.info(self, "成功", "个人资料已更新")

    def show_change_password_dialog(self):
        """显示修改密码对话框"""
        dialog = ChangePasswordDialog(self, self.username, self.authenticator)
        dialog.exec_()

    def show_deactivate_account_dialog(self):
        """显示注销账户对话框"""
        dialog = DeactivateAccountDialog(self, self.username, self.authenticator)
        if dialog.exec_() == QDialog.Accepted:
            # 用户已注销账户，退出应用
            self.close()

    def logout(self):
        """退出登录"""
        try:
            logger.info(f"用户 {self.username} 开始退出登录")
            # 设置标志，避免closeEvent中再次询问
            self._is_logging_out = True

            # 释放资源
            try:
                logger.info("正在释放主窗口资源...")
                if hasattr(self, 'authenticator'):
                    self.authenticator.close()
                    self.authenticator = None
                logger.info("主窗口资源释放完成")
            except Exception as e:
                logger.error(f"释放主窗口资源时出错: {str(e)}\n{traceback.format_exc()}")

            # 发送登出信号
            logger.info("正在发送登出信号...")
            self.logout_signal.emit()
            logger.info("登出信号已发送")

            # 等待一小段时间确保登录窗口显示
            QTimer.singleShot(100, self.close)
            logger.info("已安排窗口关闭")

        except Exception as e:
            logger.error(f"退出登录时出错: {str(e)}\n{traceback.format_exc()}")
            MessageBox.error(self, "错误", f"退出登录时出错: {str(e)}")

    def show_about(self):
        """显示关于对话框"""
        MessageBox.info(
            self,
            '关于',
            '人脸识别登录系统\n'
            '版本: 1.0.0\n'
            '© 2023 All Rights Reserved'
        )

    def show_reface_dialog(self):
        """显示重新录入人脸对话框"""
        from .register_window import RegisterWindow  # 导入注册窗口

        try:
        # 创建一个临时的注册窗口，仅用于人脸注册
        register_window = RegisterWindow(self.authenticator, parent=self)
        register_window.setWindowTitle("重新录入人脸")
            
            # 调整窗口大小，由于隐藏了许多控件，窗口可以更小
            register_window.resize(700, 450)

        # 隐藏不需要的控件
            if hasattr(register_window, 'username_input'):
        register_window.username_input.setVisible(False)
        register_window.username_label.setVisible(False)
            if hasattr(register_window, 'password_input'):
        register_window.password_input.setVisible(False)
        register_window.password_label.setVisible(False)
            if hasattr(register_window, 'confirm_password_input'):
        register_window.confirm_password_input.setVisible(False)
        register_window.confirm_password_label.setVisible(False)
            if hasattr(register_window, 'email_input'):
        register_window.email_input.setVisible(False)
        register_window.email_label.setVisible(False)
            if hasattr(register_window, 'phone_input'):
        register_window.phone_input.setVisible(False)
        register_window.phone_label.setVisible(False)
            if hasattr(register_window, 'fullname_input'):
                register_window.fullname_input.setVisible(False)
                register_window.fullname_label.setVisible(False)
            
            # 调整按钮
            if hasattr(register_window, 'register_button'):
                register_window.register_button.setText("更新人脸数据")
                register_window.register_button.setToolTip("保存新的人脸数据，替换原有数据")
                # 设置更明显的样式
                register_window.register_button.setStyleSheet(
                    "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }"
                    "QPushButton:hover { background-color: #45a049; }"
                )
            
            # 隐藏注册人脸按钮，因为在这个场景下它是多余的
            if hasattr(register_window, 'face_register_button'):
                register_window.face_register_button.setVisible(False)
            
            # 修改返回按钮文本和样式
            if hasattr(register_window, 'back_button'):
                register_window.back_button.setText("取消")
                register_window.back_button.setToolTip("取消重新录入人脸操作")
                register_window.back_button.setStyleSheet(
                    "QPushButton { padding: 6px; }"
                )

            # 修改相机按钮样式
            if hasattr(register_window, 'camera_button'):
                register_window.camera_button.setStyleSheet(
                    "QPushButton { background-color: #3498db; color: white; padding: 6px; }"
                    "QPushButton:hover { background-color: #2980b9; }"
                )

            # 重新排版按钮布局
            if hasattr(register_window, 'button_layout') and register_window.button_layout:
                # 清除原有的布局中的所有部件
                while register_window.button_layout.count():
                    item = register_window.button_layout.takeAt(0)
                    if item.widget():
                        item.widget().setParent(None)
                
                # 设置新的按钮布局 - 更大的按钮，更好的间距
                if hasattr(register_window, 'camera_button'):
                    register_window.button_layout.addWidget(register_window.camera_button, 0, 0, 1, 2)
                if hasattr(register_window, 'register_button'):
                    register_window.button_layout.addWidget(register_window.register_button, 1, 0, 1, 2)
                if hasattr(register_window, 'back_button'):
                    register_window.button_layout.addWidget(register_window.back_button, 2, 0, 1, 2)
                    
                # 添加间距
                register_window.button_layout.setVerticalSpacing(15)
                register_window.button_layout.setContentsMargins(10, 20, 10, 10)

        # 设置当前用户名
        register_window.current_username = self.username
            
            # 设置状态标签
            if hasattr(register_window, 'status_label'):
                register_window.status_label.setText(f"为用户 {self.username} 重新录入人脸")
                # 使状态标签更明显
                register_window.status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #333;")

        # 显示窗口
        register_window.show()

        # 连接信号
        register_window.register_success.connect(self.on_reface_success)
        except Exception as e:
            logger.error(f"配置重新录入人脸窗口时出错: {str(e)}\n{traceback.format_exc()}")
            MessageBox.error(self, "错误", f"无法打开重新录入人脸窗口: {str(e)}")

    def on_reface_success(self):
        """重新录入人脸成功的回调"""
        MessageBox.info(self, "成功", "人脸数据已更新")
        logger.info(f"用户 {self.username} 重新录入人脸成功")

    def showEvent(self, event):
        """窗口显示事件"""
        try:
            logger.info("主窗口显示事件触发")
            super().showEvent(event)
        except Exception as e:
            logger.error(f"处理主窗口显示事件时出错: {str(e)}\n{traceback.format_exc()}")

    def hideEvent(self, event):
        """窗口隐藏事件"""
        try:
            logger.info("主窗口隐藏事件触发")
            super().hideEvent(event)
        except Exception as e:
            logger.error(f"处理主窗口隐藏事件时出错: {str(e)}\n{traceback.format_exc()}")

    def closeEvent(self, event):
        """窗口关闭事件"""
        try:
            logger.info("主窗口关闭事件触发")
            # 执行清理操作
            if hasattr(self, 'authenticator') and self.authenticator is not None:
                self.authenticator.close()
            super().closeEvent(event)
            logger.info("主窗口已关闭")
        except Exception as e:
            logger.error(f"处理主窗口关闭事件时出错: {str(e)}\n{traceback.format_exc()}")
            event.accept()  # 确保窗口能够关闭

    def __del__(self):
        """析构函数"""
        try:
            logger.info("主窗口对象开始销毁...")
            if hasattr(self, 'authenticator') and self.authenticator is not None:
                self.authenticator.close()
            logger.info("主窗口对象销毁完成")
        except Exception as e:
            logger.error(f"销毁主窗口对象时出错: {str(e)}\n{traceback.format_exc()}")


class ProfileDialog(QDialog):
    """个人资料对话框"""

    def __init__(self, parent, user_profile, authenticator):
        super().__init__(parent)

        self.user_profile = user_profile or {}
        self.authenticator = authenticator
        self.username = user_profile.get('username', '')

        self.init_ui()

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("个人资料")
        self.setMinimumWidth(400)

        # 创建表单布局
        layout = QVBoxLayout(self)

        # 创建选项卡
        tab_widget = QTabWidget()

        # 个人信息选项卡
        info_tab = QWidget()
        info_layout = QFormLayout(info_tab)

        # 用户名（只读）
        self.username_edit = QLineEdit(self.username)
        self.username_edit.setReadOnly(True)
        info_layout.addRow("用户名:", self.username_edit)

        # 姓名
        self.full_name_edit = QLineEdit(self.user_profile.get('full_name', ''))
        info_layout.addRow("姓名:", self.full_name_edit)

        # 电子邮件
        self.email_edit = QLineEdit(self.user_profile.get('email', ''))
        info_layout.addRow("电子邮件:", self.email_edit)

        # 手机号码
        self.phone_edit = QLineEdit(self.user_profile.get('phone', ''))
        info_layout.addRow("手机号码:", self.phone_edit)

        # 注册时间（只读）
        created_at = self.user_profile.get('created_at', '')
        created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else ''
        self.created_at_edit = QLineEdit(created_at_str)
        self.created_at_edit.setReadOnly(True)
        info_layout.addRow("注册时间:", self.created_at_edit)

        # 最后登录时间（只读）
        last_login = self.user_profile.get('last_login', '')
        last_login_str = last_login.strftime('%Y-%m-%d %H:%M:%S') if last_login else ''
        self.last_login_edit = QLineEdit(last_login_str)
        self.last_login_edit.setReadOnly(True)
        info_layout.addRow("最后登录:", self.last_login_edit)

        tab_widget.addTab(info_tab, "基本信息")

        layout.addWidget(tab_widget)

        # 按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_profile)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def save_profile(self):
        """保存个人资料"""
        # 获取表单数据
        full_name = self.full_name_edit.text()
        email = self.email_edit.text()
        phone = self.phone_edit.text()

        # 更新资料
        success = self.authenticator.update_user_profile(
            self.username,
            email=email,
            phone=phone,
            full_name=full_name
        )

        if success:
            self.accept()
        else:
            MessageBox.error(self, "错误", "更新个人资料失败")


class ChangePasswordDialog(QDialog):
    """修改密码对话框"""

    def __init__(self, parent, username, authenticator):
        super().__init__(parent)

        self.username = username
        self.authenticator = authenticator

        self.init_ui()

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("修改密码")
        self.setMinimumWidth(350)

        # 创建表单布局
        layout = QFormLayout(self)

        # 当前密码
        self.current_pwd_edit = QLineEdit()
        self.current_pwd_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("当前密码:", self.current_pwd_edit)

        # 新密码
        self.new_pwd_edit = QLineEdit()
        self.new_pwd_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("新密码:", self.new_pwd_edit)

        # 确认新密码
        self.confirm_pwd_edit = QLineEdit()
        self.confirm_pwd_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("确认新密码:", self.confirm_pwd_edit)

        # 按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.change_password)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def change_password(self):
        """修改密码"""
        # 获取表单数据
        current_pwd = self.current_pwd_edit.text()
        new_pwd = self.new_pwd_edit.text()
        confirm_pwd = self.confirm_pwd_edit.text()

        # 验证表单
        if not current_pwd or not new_pwd or not confirm_pwd:
            MessageBox.warning(self, "警告", "请填写所有字段")
            return

        if new_pwd != confirm_pwd:
            MessageBox.warning(self, "警告", "两次输入的新密码不一致")
            return

        if len(new_pwd) < 6:
            MessageBox.warning(self, "警告", "新密码长度不能少于6位")
            return

        # 修改密码
        success, message = self.authenticator.change_password(
            self.username,
            current_pwd,
            new_pwd
        )

        if success:
            MessageBox.info(self, "成功", message)
            self.accept()
        else:
            MessageBox.error(self, "错误", message)


class DeactivateAccountDialog(QDialog):
    """注销账户对话框"""

    def __init__(self, parent, username, authenticator):
        super().__init__(parent)

        self.username = username
        self.authenticator = authenticator

        self.init_ui()

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("注销账户")
        self.setMinimumWidth(400)

        # 创建布局
        layout = QVBoxLayout(self)

        # 警告信息
        warning_label = QLabel(
            "警告：账户注销后将无法恢复，所有与该账户关联的数据将被标记为无效。\n"
            "请确认您真的要注销此账户。"
        )
        warning_label.setStyleSheet("color: red;")
        warning_label.setWordWrap(True)
        layout.addWidget(warning_label)

        # 密码验证
        form_layout = QFormLayout()
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.Password)
        form_layout.addRow("请输入密码确认:", self.pwd_edit)
        layout.addLayout(form_layout)

        # 确认按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.button(QDialogButtonBox.Ok).setText("确认注销")
        button_box.button(QDialogButtonBox.Ok).setStyleSheet("background-color: #FF5555;")
        button_box.accepted.connect(self.deactivate_account)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def deactivate_account(self):
        """注销账户"""
        # 获取密码
        password = self.pwd_edit.text()

        if not password:
            MessageBox.warning(self, "警告", "请输入密码")
            return

        # 再次确认
        confirm = QMessageBox.warning(
            self,
            "最终确认",
            "此操作不可逆，确定要注销您的账户吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            # 注销账户
            success, message = self.authenticator.deactivate_account(
                self.username,
                password
            )

            if success:
                MessageBox.info(self, "成功", message)
                self.accept()
            else:
                MessageBox.error(self, "错误", message)