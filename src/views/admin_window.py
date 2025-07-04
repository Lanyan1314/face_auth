#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
管理后台窗口
实现用户管理、权限管理等功能
"""

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QPushButton, QTabWidget, QTableWidget, 
                            QTableWidgetItem, QDialog, QLineEdit, QFormLayout, 
                            QComboBox, QMessageBox, QHeaderView, QAbstractItemView)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QFont
from ..database.models import UserRole
from ..auth.authenticator import Authenticator
import traceback

class AdminWindow(QMainWindow):
    """管理后台窗口"""
    
    # 定义信号
    logout_signal = pyqtSignal()
    
    def __init__(self, authenticator):
        """
        初始化管理后台窗口
        :param authenticator: 认证器对象
        """
        super().__init__()
        
        # 保存认证器
        self.authenticator = authenticator
        
        # 获取当前用户信息
        self.current_user = self.authenticator.get_current_user()
        if not self.current_user:
            raise ValueError("无法获取当前用户信息")
        
        # 确保用户具有管理员权限
        if not self.authenticator.is_admin():
            raise ValueError("用户没有管理员权限")
        
        # 初始化界面
        self.init_ui()
    
    def init_ui(self):
        """初始化界面"""
        try:
            # 设置窗口属性
            self.setWindowTitle("人脸认证系统 - 管理后台")
            self.setMinimumSize(1024, 768)  # 增加最小尺寸
            self.resize(1280, 800)  # 设置默认尺寸
        
            # 创建中央部件
            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            
            # 主布局
            main_layout = QVBoxLayout(central_widget)
            
            # 顶部信息栏
            info_layout = QHBoxLayout()
            
            # 当前用户信息
            user_info = f"当前用户: {self.current_user.get('username', 'Unknown')} ({self.current_user.get('role_name', 'Unknown')})"
            user_info_label = QLabel(user_info)
            user_info_label.setStyleSheet("font-weight: bold;")
            info_layout.addWidget(user_info_label)
            
            # 添加弹性空间
            info_layout.addStretch()
            
            # 退出登录按钮
            logout_btn = QPushButton("退出登录")
            logout_btn.clicked.connect(self.handle_logout)
            info_layout.addWidget(logout_btn)
            
            main_layout.addLayout(info_layout)
            
            # 创建选项卡
            self.tab_widget = QTabWidget()
            
            # 用户管理选项卡
            self.user_tab = QWidget()
            self.init_user_tab()
            self.tab_widget.addTab(self.user_tab, "用户管理")
            
            # 系统信息选项卡
            self.system_tab = QWidget()
            self.init_system_tab()
            self.tab_widget.addTab(self.system_tab, "系统信息")
            
            main_layout.addWidget(self.tab_widget)
            
            # 加载用户数据
            self.load_user_data()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"初始化管理后台失败: {str(e)}")
            print(f"初始化管理后台出错: {str(e)}\n{traceback.format_exc()}")
    
    def init_user_tab(self):
        """初始化用户管理选项卡"""
        layout = QVBoxLayout(self.user_tab)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        
        # 创建用户按钮
        self.create_user_btn = QPushButton("创建用户")
        self.create_user_btn.clicked.connect(self.show_create_user_dialog)
        btn_layout.addWidget(self.create_user_btn)
        
        # 创建管理员按钮（仅限超级管理员）
        self.create_admin_btn = QPushButton("创建管理员")
        self.create_admin_btn.clicked.connect(self.show_create_admin_dialog)
        if not self.authenticator.is_super_admin():
            self.create_admin_btn.setEnabled(False)
            self.create_admin_btn.setToolTip("仅限最高管理员使用")
        btn_layout.addWidget(self.create_admin_btn)
        
        # 刷新按钮
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self.load_user_data)
        btn_layout.addWidget(refresh_btn)
        
        # 添加弹性空间
        btn_layout.addStretch()
        
        # 用户筛选下拉框
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("所有用户", None)
        self.filter_combo.addItem("普通用户", UserRole.USER.value)
        self.filter_combo.addItem("管理员", UserRole.ADMIN.value)
        self.filter_combo.addItem("最高管理员", UserRole.SUPER_ADMIN.value)
        self.filter_combo.currentIndexChanged.connect(self.load_user_data)
        btn_layout.addWidget(QLabel("筛选:"))
        btn_layout.addWidget(self.filter_combo)
        
        layout.addLayout(btn_layout)
        
        # 用户表格
        self.user_table = QTableWidget()
        self.user_table.setColumnCount(7)
        self.user_table.setHorizontalHeaderLabels(["ID", "用户名", "姓名", "邮箱", "角色", "创建时间", "操作"])
        self.user_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 不可编辑
        self.user_table.setSelectionBehavior(QAbstractItemView.SelectRows)  # 选择整行
        self.user_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 列宽自适应
        
        layout.addWidget(self.user_table)
    
    def init_system_tab(self):
        """初始化系统信息选项卡"""
        layout = QVBoxLayout(self.system_tab)
        
        # 系统信息标签
        system_info = QLabel("系统信息")
        system_info.setAlignment(Qt.AlignCenter)
        system_info.setFont(QFont("Arial", 14))
        layout.addWidget(system_info)
        
        # 版本信息
        version_info = QLabel("人脸认证系统 v1.0.0")
        version_info.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_info)
        
        # 添加弹性空间
        layout.addStretch()
    
    def load_user_data(self):
        """加载用户数据"""
        try:
            # 获取筛选条件
            filter_role = self.filter_combo.currentData()
            
            # 获取用户列表
            users, message = self.authenticator.get_users_by_role(filter_role)
            
            if not users:
                QMessageBox.warning(self, "错误", message)
                return
            
            # 清空表格
            self.user_table.setRowCount(0)
            
            # 填充表格
            for user in users:
                row_position = self.user_table.rowCount()
                self.user_table.insertRow(row_position)
                
                # 设置单元格内容
                self.user_table.setItem(row_position, 0, QTableWidgetItem(str(user['id'])))
                self.user_table.setItem(row_position, 1, QTableWidgetItem(user['username']))
                self.user_table.setItem(row_position, 2, QTableWidgetItem(user['full_name'] or ""))
                self.user_table.setItem(row_position, 3, QTableWidgetItem(user['email'] or ""))
                self.user_table.setItem(row_position, 4, QTableWidgetItem(user['role_name']))
                self.user_table.setItem(row_position, 5, QTableWidgetItem(str(user['created_at'])))
                
                # 操作按钮
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(0, 0, 0, 0)
                
                # 重置密码按钮
                reset_pwd_btn = QPushButton("重置密码")
                reset_pwd_btn.clicked.connect(lambda checked, u=user['username']: self.show_reset_password_dialog(u))
                actions_layout.addWidget(reset_pwd_btn)
                
                # 修改角色按钮（仅限超级管理员）
                change_role_btn = QPushButton("修改角色")
                change_role_btn.clicked.connect(lambda checked, u=user['username'], r=user['role']: self.show_change_role_dialog(u, r))
                
                # 禁用修改角色按钮（如果没有权限）
                if not self.authenticator.is_super_admin() or user['role'] >= UserRole.ADMIN.value:
                    change_role_btn.setEnabled(False)
                    change_role_btn.setToolTip("仅限最高管理员修改")
                
                actions_layout.addWidget(change_role_btn)
                
                # 删除按钮
                delete_btn = QPushButton("删除")
                delete_btn.clicked.connect(lambda checked, u=user['username']: self.confirm_delete_user(u))
                
                # 禁用删除按钮（如果是管理员且当前用户不是超级管理员）
                if user['role'] >= UserRole.ADMIN.value and not self.authenticator.is_super_admin():
                    delete_btn.setEnabled(False)
                    delete_btn.setToolTip("仅限最高管理员删除")
                
                # 禁用删除自己
                if user['username'] == self.current_user['username']:
                    delete_btn.setEnabled(False)
                    delete_btn.setToolTip("不能删除自己")
                
                actions_layout.addWidget(delete_btn)
                
                self.user_table.setCellWidget(row_position, 6, actions_widget)
        
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载用户数据失败: {str(e)}")
            print(f"加载用户数据出错: {str(e)}\n{traceback.format_exc()}")
    
    def show_create_user_dialog(self):
        """显示创建用户对话框"""
        dialog = UserDialog(self, is_admin=False)
        if dialog.exec_() == QDialog.Accepted:
            # 获取表单数据
            username = dialog.username_edit.text().strip()
            password = dialog.password_edit.text()
            email = dialog.email_edit.text().strip()
            phone = dialog.phone_edit.text().strip()
            full_name = dialog.name_edit.text().strip()
            
            # 创建用户
            success = self.authenticator.register_user(username, password, email, phone, full_name)
            
            if success:
                QMessageBox.information(self, "成功", f"已成功创建用户 {username}")
                self.load_user_data()  # 刷新用户列表
            else:
                QMessageBox.warning(self, "失败", "创建用户失败，可能用户名已存在")
    
    def show_create_admin_dialog(self):
        """显示创建管理员对话框"""
        dialog = UserDialog(self, is_admin=True)
        if dialog.exec_() == QDialog.Accepted:
            # 获取表单数据
            username = dialog.username_edit.text().strip()
            password = dialog.password_edit.text()
            email = dialog.email_edit.text().strip()
            phone = dialog.phone_edit.text().strip()
            full_name = dialog.name_edit.text().strip()
            
            # 创建管理员
            success, message = self.authenticator.create_admin(username, password, email, phone, full_name)
            
            if success:
                QMessageBox.information(self, "成功", message)
                self.load_user_data()  # 刷新用户列表
            else:
                QMessageBox.warning(self, "失败", message)
    
    def show_reset_password_dialog(self, username):
        """
        显示重置密码对话框
        :param username: 要重置密码的用户名
        """
        dialog = ResetPasswordDialog(self, username)
        if dialog.exec_() == QDialog.Accepted:
            # 获取新密码
            new_password = dialog.password_edit.text()
            
            # 重置密码
            success, message = self.authenticator.reset_user_password(username, new_password)
            
            if success:
                QMessageBox.information(self, "成功", message)
            else:
                QMessageBox.warning(self, "失败", message)
    
    def show_change_role_dialog(self, username, current_role):
        """
        显示修改角色对话框
        :param username: 要修改角色的用户名
        :param current_role: 当前角色
        """
        dialog = ChangeRoleDialog(self, username, current_role)
        if dialog.exec_() == QDialog.Accepted:
            # 获取新角色
            new_role = dialog.role_combo.currentData()
            
            # 修改角色
            success, message = self.authenticator.update_user_role(username, new_role)
            
            if success:
                QMessageBox.information(self, "成功", message)
                self.load_user_data()  # 刷新用户列表
            else:
                QMessageBox.warning(self, "失败", message)
    
    def confirm_delete_user(self, username):
        """
        确认删除用户
        :param username: 要删除的用户名
        """
        reply = QMessageBox.question(
            self, "确认删除", 
            f"确定要删除用户 {username} 吗？此操作不可撤销！",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message = self.authenticator.delete_user(username)
            
            if success:
                QMessageBox.information(self, "成功", message)
                self.load_user_data()  # 刷新用户列表
            else:
                QMessageBox.warning(self, "失败", message)
    
    def handle_logout(self):
        """处理退出登录"""
        self.authenticator.logout()
        self.logout_signal.emit()
        self.close()


class UserDialog(QDialog):
    """用户信息对话框"""
    
    def __init__(self, parent=None, is_admin=False):
        """
        初始化对话框
        :param parent: 父窗口
        :param is_admin: 是否为管理员
        """
        super().__init__(parent)
        
        self.is_admin = is_admin
        self.init_ui()
    
    def init_ui(self):
        """初始化界面"""
        # 设置窗口属性
        self.setWindowTitle("创建" + ("管理员" if self.is_admin else "用户"))
        self.setMinimumWidth(300)
        
        # 创建表单布局
        layout = QFormLayout(self)
        
        # 用户名输入框
        self.username_edit = QLineEdit()
        layout.addRow("用户名:", self.username_edit)
        
        # 密码输入框
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("密码:", self.password_edit)
        
        # 姓名输入框
        self.name_edit = QLineEdit()
        layout.addRow("姓名:", self.name_edit)
        
        # 邮箱输入框
        self.email_edit = QLineEdit()
        layout.addRow("邮箱:", self.email_edit)
        
        # 手机号输入框
        self.phone_edit = QLineEdit()
        layout.addRow("手机号:", self.phone_edit)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        
        # 确定按钮
        ok_btn = QPushButton("确定")
        ok_btn.clicked.connect(self.validate_and_accept)
        btn_layout.addWidget(ok_btn)
        
        # 取消按钮
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addRow("", btn_layout)
    
    def validate_and_accept(self):
        """验证表单并接受"""
        # 验证用户名
        if not self.username_edit.text().strip():
            QMessageBox.warning(self, "错误", "用户名不能为空")
            return
        
        # 验证密码
        if not self.password_edit.text():
            QMessageBox.warning(self, "错误", "密码不能为空")
            return
        
        # 接受对话框
        self.accept()


class ResetPasswordDialog(QDialog):
    """重置密码对话框"""
    
    def __init__(self, parent=None, username=""):
        """
        初始化对话框
        :param parent: 父窗口
        :param username: 用户名
        """
        super().__init__(parent)
        
        self.username = username
        self.init_ui()
    
    def init_ui(self):
        """初始化界面"""
        # 设置窗口属性
        self.setWindowTitle(f"重置密码 - {self.username}")
        self.setMinimumWidth(300)
        
        # 创建表单布局
        layout = QFormLayout(self)
        
        # 新密码输入框
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("新密码:", self.password_edit)
        
        # 确认密码输入框
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        layout.addRow("确认密码:", self.confirm_password_edit)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        
        # 确定按钮
        ok_btn = QPushButton("确定")
        ok_btn.clicked.connect(self.validate_and_accept)
        btn_layout.addWidget(ok_btn)
        
        # 取消按钮
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addRow("", btn_layout)
    
    def validate_and_accept(self):
        """验证表单并接受"""
        # 验证密码
        password = self.password_edit.text()
        confirm_password = self.confirm_password_edit.text()
        
        if not password:
            QMessageBox.warning(self, "错误", "密码不能为空")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "错误", "两次输入的密码不一致")
            return
        
        # 接受对话框
        self.accept()


class ChangeRoleDialog(QDialog):
    """修改角色对话框"""
    
    def __init__(self, parent=None, username="", current_role=UserRole.USER.value):
        """
        初始化对话框
        :param parent: 父窗口
        :param username: 用户名
        :param current_role: 当前角色
        """
        super().__init__(parent)
        
        self.username = username
        self.current_role = current_role
        self.init_ui()
    
    def init_ui(self):
        """初始化界面"""
        # 设置窗口属性
        self.setWindowTitle(f"修改角色 - {self.username}")
        self.setMinimumWidth(300)
        
        # 创建表单布局
        layout = QFormLayout(self)
        
        # 角色下拉框
        self.role_combo = QComboBox()
        self.role_combo.addItem("普通用户", UserRole.USER.value)
        self.role_combo.addItem("管理员", UserRole.ADMIN.value)
        self.role_combo.addItem("最高管理员", UserRole.SUPER_ADMIN.value)
        
        # 设置当前角色
        index = self.role_combo.findData(self.current_role)
        if index >= 0:
            self.role_combo.setCurrentIndex(index)
        
        layout.addRow("角色:", self.role_combo)
        
        # 按钮区域
        btn_layout = QHBoxLayout()
        
        # 确定按钮
        ok_btn = QPushButton("确定")
        ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(ok_btn)
        
        # 取消按钮
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addRow("", btn_layout) 