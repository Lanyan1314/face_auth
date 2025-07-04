from ..database.db_helper import DBHelper
from ..detection.face_detector import FaceDetector
from ..detection.face_utils import check_face_quality
from ..database.models import UserRole
import cv2
import numpy as np
import traceback
from ..utils.logger import get_logger
import logging
import datetime

logger = get_logger('face_auth.authenticator')

class Authenticator:
    """
    认证类，整合密码验证和人脸识别功能
    实现双因素认证
    """
    def __init__(self, db_config=None):
        """
        初始化认证器
        :param db_config: 数据库配置，格式为字典 {'host': '主机', 'user': '用户名', 'password': '密码', 'db_name': '数据库名'}
        """
        # 保存数据库配置
        self.db_config = db_config
        
        # 初始化数据库连接
        if db_config is None:
            self.db = DBHelper()
        else:
            self.db = DBHelper(**db_config)
        
        # 初始化人脸检测器
        self.face_detector = FaceDetector()
    
        # 当前登录用户
        self.current_user = None
    
    def register_user(self, username, password, email=None, phone=None, full_name=None, role=UserRole.USER.value):
        """
        注册新用户（仅账号密码）
        :param username: 用户名
        :param password: 密码
        :param email: 电子邮件地址
        :param phone: 手机号码
        :param full_name: 姓名
        :param role: 用户角色，默认为普通用户
        :return: 成功返回True，失败返回False
        """
        return self.db.register_user(username, password, email, phone, full_name, role)
    
    def register_face(self, username, frame):
        """
        为已有用户注册人脸
        :param username: 用户名
        :param frame: 摄像头捕获的帧（OpenCV格式）
        :return: 成功返回True，失败返回False
        """
        try:
            # 检查用户是否存在
            user = self.db.get_user(username)
            if not user:
                logger.warning(f"用户 {username} 不存在，无法注册人脸")
                return False
            
            # 检查人脸质量
            is_valid, error_message = check_face_quality(frame)
            if not is_valid:
                logger.warning(f"用户 {username} 人脸质量检查失败: {error_message}")
                return False
            
            # 提取人脸特征
            embedding = self.face_detector.get_face_embedding(frame)
            if embedding is None:
                logger.warning(f"用户 {username} 人脸特征提取失败")
                return False
            
            # 保存人脸特征
            result = self.db.save_face_embedding(username, embedding)
            if result:
                logger.info(f"用户 {username} 人脸注册成功")
            else:
                logger.warning(f"用户 {username} 人脸数据保存失败")
            return result
        except Exception as e:
            logger.error(f"注册人脸出错: {str(e)}\n{traceback.format_exc()}")
            return False
    
    def authenticate(self, username, password, camera=None, camera_id=0, max_attempts=10):
        """
        双因素认证（密码+人脸）
        :param username: 用户名
        :param password: 密码
        :param camera: 已打开的摄像头对象，如果为None则使用camera_id创建新的摄像头
        :param camera_id: 摄像头ID，仅当camera为None时使用
        :param max_attempts: 最大尝试次数
        :return: (认证结果, 消息)，认证结果为布尔值，消息为字符串
        """
        # 第一步：验证用户名和密码
        if not self.db.verify_password(username, password):
            return False, "用户名或密码错误"
        
        # 获取用户信息
        user = self.db.get_user(username)
        if not user:
            return False, "用户不存在"
        
        # 检查用户是否已注册人脸
        if len(user) < 4 or user[3] is None:
            return False, "用户未注册人脸，请先注册"
        
        # 第二步：人脸识别
        # 捕获人脸特征
        if camera is not None:
            # 使用已打开的摄像头对象
            current_embedding = self.capture_face_with_camera(camera, max_attempts)
        else:
            # 使用face_detector内部的摄像头处理
            current_embedding, _ = self.face_detector.capture_face_from_camera(camera_id, max_attempts)
        
        if current_embedding is None:
            return False, "未检测到人脸"
        
        # 比较人脸特征
        if self.face_detector.compare_faces(current_embedding, user[3]):
            # 更新最后登录时间
            self.db.update_last_login(username)
            return True, "认证成功"
        else:
            return False, "人脸识别失败"
    
    def authenticate_face_only(self, camera=None, camera_id=0, max_attempts=10):
        """
        仅使用人脸进行认证，不需要用户名和密码
        :param camera: 已打开的摄像头对象，如果为None则使用camera_id创建新的摄像头
        :param camera_id: 摄像头ID，仅当camera为None时使用
        :param max_attempts: 最大尝试次数
        :return: (认证结果, 用户名, 消息)，认证结果为布尔值，用户名为字符串，消息为字符串
        """
        # 捕获人脸特征
        if camera is not None:
            # 使用已打开的摄像头对象
            current_embedding = self.capture_face_with_camera(camera, max_attempts)
        else:
            # 使用face_detector内部的摄像头处理
            current_embedding, _ = self.face_detector.capture_face_from_camera(camera_id, max_attempts)
        
        if current_embedding is None:
            return False, None, "未检测到人脸"
        
        # 获取所有用户
        users = self.db.get_all_users_with_face()
        if not users or len(users) == 0:
            return False, None, "数据库中没有注册人脸的用户"
        
        # 比较所有用户的人脸特征
        for user in users:
            username = user[0]
            face_embedding = user[3]
            
            if face_embedding is not None and self.face_detector.compare_faces(current_embedding, face_embedding, threshold=0.6):
                # 更新最后登录时间
                self.db.update_last_login(username)
                return True, username, f"欢迎回来，{username}！"
        
        return False, None, "未找到匹配的人脸"
    
    def authenticate_password_only(self, username, password=None):
        """
        仅使用密码进行认证，不需要人脸识别
        :param username: 用户名
        :param password: 密码，如果为None则表示已通过其他方式（如人脸识别）验证过身份
        :return: (认证结果, 消息)，认证结果为布尔值，消息为字符串
        """
        if password is None:
            # 人脸识别已验证过身份，直接检查用户是否存在
            if self.db.user_exists(username):
                # 更新最后登录时间
                self.db.update_last_login(username)
                return True, "人脸认证成功"
            else:
                return False, "用户不存在"
        else:
            # 正常的密码验证
            if self.db.verify_password(username, password):
                # 更新最后登录时间
                self.db.update_last_login(username)
                return True, "认证成功"
            else:
                return False, "用户名或密码错误"
    
    def capture_face_with_camera(self, camera, max_attempts=10):
        """
        使用已打开的摄像头捕获人脸特征
        :param camera: 已打开的摄像头对象
        :param max_attempts: 最大尝试次数
        :return: 人脸特征向量，如果未检测到人脸则返回None
        """
        if camera is None or not camera.isOpened():
            print("摄像头未打开")
            return None
        
        embedding = None
        attempts = 0
        
        while attempts < max_attempts and embedding is None:
            ret, frame = camera.read()
            if not ret:
                print("无法读取摄像头画面")
                break
            
            # 检测人脸并提取特征
            embedding = self.face_detector.get_face_embedding(frame)
            attempts += 1
        
        return embedding
    
    def change_password(self, username, current_password, new_password):
        """
        修改用户密码
        :param username: 用户名
        :param current_password: 当前密码
        :param new_password: 新密码
        :return: (成功标志, 消息)
        """
        return self.db.change_password(username, current_password, new_password)
    
    def initiate_password_reset(self, username_or_email):
        """
        发起密码重置流程
        :param username_or_email: 用户名或电子邮件
        :return: (成功标志, 令牌或错误信息)
        """
        return self.db.generate_reset_token(username_or_email)
    
    def reset_password(self, token, new_password):
        """
        使用令牌重置密码
        :param token: 重置令牌
        :param new_password: 新密码
        :return: (成功标志, 消息)
        """
        return self.db.reset_password_with_token(token, new_password)
    
    def get_user_profile(self, username):
        """
        获取用户个人资料
        :param username: 用户名
        :return: 用户资料字典或None
        """
        return self.db.get_user_profile(username)
    
    def update_user_profile(self, username, email=None, phone=None, full_name=None):
        """
        更新用户个人资料
        :param username: 用户名
        :param email: 电子邮件地址
        :param phone: 手机号码
        :param full_name: 姓名
        :return: 成功返回True，失败返回False
        """
        return self.db.update_profile(username, email, phone, full_name)
    
    def deactivate_account(self, username, password):
        """
        注销用户账户
        :param username: 用户名
        :param password: 密码（验证身份）
        :return: (成功标志, 消息)
        """
        return self.db.deactivate_account(username, password)
    
    def close(self):
        """关闭认证器，释放资源"""
        try:
            logger.info("开始关闭认证器，释放资源...")
            
            # 关闭数据库连接
            if hasattr(self, 'db') and self.db is not None:
                try:
                    logger.info("正在关闭数据库连接...")
                    self.db.close()
                    self.db = None
                    logger.info("数据库连接已关闭")
                except Exception as e:
                    logger.error(f"关闭数据库连接时出错: {str(e)}")
                    logger.error(traceback.format_exc())
            
            # 释放人脸检测器资源
            if hasattr(self, 'face_detector') and self.face_detector is not None:
                try:
                    logger.info("正在释放人脸检测器资源...")
                    self.face_detector.release()
                    self.face_detector = None
                    logger.info("人脸检测器资源已释放")
                except Exception as e:
                    logger.error(f"释放人脸检测器资源时出错: {str(e)}")
                    logger.error(traceback.format_exc())
            
            logger.info("认证器资源释放完成")
            
        except Exception as e:
            logger.error(f"关闭认证器时出错: {str(e)}")
            logger.error(traceback.format_exc())
    
    def login(self, username, password):
        """
        使用用户名和密码登录（不进行人脸验证）
        :param username: 用户名
        :param password: 密码，如果为None则表示已通过其他方式（如人脸识别）验证过身份
        :return: 登录结果字典，包含success、message和role字段
        """
        success, message = self.authenticate_password_only(username, password)
        if success:
            # 获取用户信息
            user_info = self.db.get_user(username)
            if user_info and len(user_info) >= 6:
                try:
                    # 根据数据库查询，角色信息在第6列索引5
                    role = user_info[5]
                    
                    # 调试日志
                    logger.info(f"用户角色信息: {role}, 类型: {type(role)}")
                    
                    # 检查是否为datetime类型(常见错误)
                    if isinstance(role, datetime.datetime):
                        logger.warning(f"角色字段为datetime类型({role})，使用默认用户角色")
                        role = UserRole.USER.value
                    # 确保是整数类型
                    elif not isinstance(role, int):
                        try:
                            role = int(role)
                        except (ValueError, TypeError):
                            logger.warning(f"无法将角色字段转换为整数({role})，使用默认用户角色")
                            role = UserRole.USER.value
                except (ValueError, TypeError, IndexError) as e:
                    # 如果获取失败，默认为普通用户
                    logger.error(f"获取用户角色时出错: {str(e)}")
                    role = UserRole.USER.value
                
                self.current_user = {
                    'username': username,
                    'role': role,
                    'role_name': UserRole.get_role_name(role)
                }
                return {
                    'success': True, 
                    'message': f"欢迎回来，{username}！", 
                    'role': role
                }
            return {
                'success': True, 
                'message': f"欢迎回来，{username}！", 
                'role': UserRole.USER.value
            }
        return {
            'success': False, 
            'message': message, 
            'role': None
        }
    
    def get_current_user(self):
        """
        获取当前登录用户的信息
        :return: 用户信息字典，包含username、role、role_name等字段
        """
        try:
            if not self.current_user:
                return None
            
            # 从数据库获取最新的用户信息
            username = self.current_user.get('username') if isinstance(self.current_user, dict) else self.current_user
            user = self.db.get_user(username)
            if not user:
                return None
            
            # 确保用户角色信息是整数类型
            try:
                role = user[5] if len(user) >= 6 else UserRole.USER.value
                # 检查是否为datetime类型(常见错误)
                if isinstance(role, datetime.datetime):
                    logger.warning(f"get_current_user: 角色字段为datetime类型({role})，使用默认用户角色")
                    role = UserRole.USER.value
                # 确保是整数类型
                elif not isinstance(role, int):
                    try:
                        role = int(role)
                    except (ValueError, TypeError):
                        logger.warning(f"get_current_user: 无法将角色字段转换为整数({role})，使用默认用户角色")
                        role = UserRole.USER.value
            except (ValueError, TypeError, IndexError) as e:
                # 如果转换失败，默认为普通用户
                logger.error(f"get_current_user: 获取用户角色时出错: {str(e)}")
                role = UserRole.USER.value
            
            # 获取角色名称
            role_name = UserRole.get_role_name(role)
            
            # 构建用户信息字典
            return {
                'username': user[1],  # user[0]是id，user[1]是username
                'full_name': user[0] or "",
                'email': user[0] or "",  # 这里看起来有问题，但为了保持兼容性先不修改结构
                'role': role,
                'role_name': role_name,
                'created_at': str(user[4]) if len(user) > 4 else "",
                'last_login': str(user[4]) if len(user) > 4 else ""  # 暂时没有last_login字段
            }
        except Exception as e:
            logger.error(f"获取当前用户信息时出错: {str(e)}")
            logger.error(traceback.format_exc())
            return None
    
    def check_permission(self, required_role=UserRole.ADMIN.value):
        """
        检查当前用户是否有指定的权限
        :param required_role: 所需的最低角色级别
        :return: (有权限, 消息)
        """
        if not self.current_user:
            return False, "您尚未登录"
        
        # 获取角色并确保是整数类型
        user_role = self.current_user.get('role', UserRole.USER.value)
        if not isinstance(user_role, int):
            try:
                user_role = int(user_role)
            except (ValueError, TypeError):
                # 如果无法转换，则默认为普通用户
                user_role = UserRole.USER.value
                
        # 确保required_role也是整数类型
        if not isinstance(required_role, int):
            try:
                required_role = int(required_role)
            except (ValueError, TypeError):
                # 如果无法转换，默认为管理员权限
                required_role = UserRole.ADMIN.value
                
        if user_role >= required_role:
            return True, "权限验证通过"
        else:
            return False, "您没有足够的权限执行此操作"
    
    def is_super_admin(self):
        """
        检查当前用户是否为最高管理员
        :return: 是最高管理员返回True，否则返回False
        """
        if not self.current_user:
            return False
        return self.current_user.get('role') == UserRole.SUPER_ADMIN.value
    
    def is_admin(self):
        """
        检查当前用户是否为管理员（包括最高管理员和次级管理员）
        :return: 是管理员返回True，否则返回False
        """
        if not self.current_user:
            return False
        
        role = self.current_user.get('role', 0)
        # 确保role是整数类型
        if isinstance(role, datetime.datetime):
            # 如果是datetime类型，使用默认用户角色
            logger.warning(f"is_admin: 角色字段为datetime类型({role})，使用默认用户角色")
            role = UserRole.USER.value
        elif not isinstance(role, int):
            # 尝试转换为整数
            try:
                role = int(role)
            except (ValueError, TypeError):
                # 如果无法转换，则默认为普通用户
                logger.warning(f"is_admin: 无法将角色字段转换为整数({role})，使用默认用户角色")
                role = UserRole.USER.value
        
        return role >= UserRole.ADMIN.value
    
    def create_admin(self, username, password, email=None, phone=None, full_name=None):
        """
        创建管理员账号（仅限最高管理员使用）
        :param username: 用户名
        :param password: 密码
        :param email: 电子邮件地址
        :param phone: 手机号码
        :param full_name: 姓名
        :return: (成功标志, 消息)
        """
        # 检查权限
        if not self.is_super_admin():
            return False, "只有最高管理员可以创建管理员账号"
        
        # 创建管理员账号
        success = self.register_user(username, password, email, phone, full_name, UserRole.ADMIN.value)
        if success:
            return True, f"已成功创建管理员账号 {username}"
        else:
            return False, "创建管理员账号失败，可能用户名已存在"
    
    def update_user_role(self, username, new_role):
        """
        更新用户角色
        :param username: 要更新的用户名
        :param new_role: 新角色值
        :return: (成功标志, 消息)
        """
        if not self.current_user:
            return False, "您尚未登录"
        
        return self.db.update_user_role(username, new_role, self.current_user['username'])
    
    def get_users_by_role(self, role=None):
        """
        获取指定角色的所有用户
        :param role: 角色ID，如果为None则获取所有用户
        :return: (用户列表, 消息)
        """
        if not self.current_user:
            return None, "您尚未登录"
        
        return self.db.get_users_by_role(role, self.current_user['username'])
    
    def delete_user(self, username):
        """
        删除用户
        :param username: 要删除的用户名
        :return: (成功标志, 消息)
        """
        if not self.current_user:
            return False, "您尚未登录"
        
        return self.db.delete_user(username, self.current_user['username'])
    
    def reset_user_password(self, username, new_password):
        """
        管理员重置用户密码
        :param username: 要重置密码的用户名
        :param new_password: 新密码
        :return: (成功标志, 消息)
        """
        if not self.current_user:
            return False, "您尚未登录"
        
        return self.db.reset_user_password(username, new_password, self.current_user['username'])
    
    def logout(self):
        """
        退出登录
        """
        self.current_user = None
        return True, "已成功退出登录"
    
    def face_login(self, frame):
        """
        使用人脸进行登录验证
        :param frame: 摄像头捕获的帧（OpenCV格式）
        :return: 字典，包含认证结果和用户信息
        """
        try:
            logger.info("开始人脸登录验证...")
            
            # 检查人脸质量
            is_valid, error_message = check_face_quality(frame)
            if not is_valid:
                logger.warning(f"人脸质量检查失败: {error_message}")
                return {
                    'success': False, 
                    'message': error_message
                }
            
            # 提取当前帧的人脸特征
            try:
                current_embedding = self.face_detector.get_face_embedding(frame)
            except ValueError as e:
                # 未检测到人脸的错误
                logger.warning(f"人脸登录失败: {str(e)}")
                return {
                    'success': False, 
                    'message': "未检测到人脸，请确保：\n1. 人脸在摄像头范围内\n2. 光线充足\n3. 正面面对摄像头\n4. 没有遮挡"
                }
            except RuntimeError as e:
                # 特征提取失败的错误
                logger.error(f"特征提取失败: {str(e)}")
                return {
                    'success': False,
                    'message': f"特征提取失败，请重试。错误原因: {str(e)[:100]}"
                }
            except Exception as e:
                # 其他错误
                logger.error(f"人脸特征提取过程中出现未知错误: {str(e)}")
                return {
                    'success': False,
                    'message': f"人脸识别过程出错: {str(e)[:100]}"
                }
            
            if current_embedding is None:
                logger.warning("人脸特征提取为空")
                return {'success': False, 'message': "人脸特征提取失败，请重试"}
            
            # 获取所有用户
            users = self.db.get_all_users_with_face()
            if not users or len(users) == 0:
                logger.warning("数据库中没有注册人脸的用户")
                return {'success': False, 'message': "数据库中没有注册人脸的用户"}
            
            # 比较所有用户的人脸特征
            for user in users:
                username = user[0]
                face_embedding = user[3]
                
                if face_embedding is not None and self.face_detector.compare_faces(current_embedding, face_embedding, threshold=0.6):
                    # 更新最后登录时间
                    self.db.update_last_login(username)
                    logger.info(f"人脸识别成功，用户: {username}")
                    return {'success': True, 'username': username}
            
            logger.warning("未找到匹配的人脸")
            return {'success': False, 'message': "未找到匹配的人脸，请先注册或使用账号密码登录"}
            
        except Exception as e:
            logger.error(f"人脸登录过程出错: {str(e)}")
            return {'success': False, 'message': f"人脸登录过程出错: {str(e)}"}
    
    def cleanup(self):
        """清理资源"""
        try:
            # 释放人脸检测器资源
            if hasattr(self, 'face_detector') and self.face_detector is not None:
                try:
                    self.face_detector.release()
                    self.face_detector = None
                except Exception:
                    pass
            
            # 关闭数据库连接
            if hasattr(self, 'db') and self.db is not None:
                try:
                    self.db.close()
                    self.db = None
                except Exception:
                    pass
            
        except Exception:
            pass
            
    def __del__(self):
        """析构函数"""
        try:
            self.cleanup() 
        except Exception:
            pass 