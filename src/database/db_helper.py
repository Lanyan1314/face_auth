import pymysql
import numpy as np
import hashlib
import datetime
import secrets
import string
from .models import UserRole

class DBHelper:
    """
    数据库操作类，负责与MySQL数据库的交互
    """
    def __init__(self, host='localhost', user='root', password='', db_name='face_auth', 
                 port=3306, charset='utf8mb4', connect_timeout=5, max_retries=3):
        """
        初始化数据库连接
        :param host: 数据库主机地址
        :param user: 数据库用户名
        :param password: 数据库密码
        :param db_name: 数据库名称
        :param port: 数据库端口
        :param charset: 字符集
        :param connect_timeout: 连接超时时间（秒）
        :param max_retries: 最大重试次数
        """
        try:
            self.conn = pymysql.connect(
                host=host,
                user=user,
                password=password,
                charset=charset,
                port=port,
                connect_timeout=connect_timeout
            )
            self.cursor = self.conn.cursor()
            
            # 创建数据库（如果不存在）
            self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            self.conn.select_db(db_name)
            
            # 创建用户表（如果不存在）
            self.create_tables()
        except pymysql.err.OperationalError as e:
            print(f"数据库连接错误: {e}")
            # 重新抛出异常，让上层处理
            raise
        except Exception as e:
            print(f"初始化数据库时出错: {e}")
            raise
    
    def create_tables(self):
        """创建必要的数据表"""
        # 扩展用户表，添加个人资料字段和密码重置相关字段，以及角色字段
        create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            face_embedding MEDIUMBLOB,
            email VARCHAR(100),
            phone VARCHAR(20),
            full_name VARCHAR(100),
            reset_token VARCHAR(100),
            reset_token_expires DATETIME,
            last_login DATETIME,
            role INT DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """
        self.cursor.execute(create_users_table)
        self.conn.commit()
    
        # 检查是否需要创建超级管理员
        self.create_super_admin_if_not_exists()
    
    def create_super_admin_if_not_exists(self):
        """
        如果系统中没有超级管理员，则创建一个默认的超级管理员账号
        默认用户名: admin
        默认密码: admin123
        """
        try:
            # 检查是否已有超级管理员
            sql = "SELECT COUNT(*) FROM users WHERE role = %s"
            self.cursor.execute(sql, (UserRole.SUPER_ADMIN.value,))
            count = self.cursor.fetchone()[0]
            
            if count == 0:
                # 创建默认超级管理员
                hashed_password = hashlib.sha256("admin123".encode()).hexdigest()
                sql = """
                INSERT INTO users 
                (username, password, email, full_name, role) 
                VALUES (%s, %s, %s, %s, %s)
                """
                self.cursor.execute(sql, ("admin", hashed_password, "admin@example.com", "系统管理员", UserRole.SUPER_ADMIN.value))
                self.conn.commit()
                print("已创建默认超级管理员账号，用户名: admin，密码: admin123")
        except Exception as e:
            print(f"创建默认超级管理员时出错: {e}")
    
    def register_user(self, username, password, email=None, phone=None, full_name=None, role=UserRole.USER.value):
        """
        注册新用户
        :param username: 用户名
        :param password: 密码（将被加密存储）
        :param email: 电子邮件地址
        :param phone: 手机号码
        :param full_name: 姓名
        :param role: 用户角色，默认为普通用户
        :return: 成功返回True，失败返回False
        """
        try:
            # 对密码进行SHA256加密
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            # 插入用户记录
            sql = """
            INSERT INTO users 
            (username, password, email, phone, full_name, role) 
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            self.cursor.execute(sql, (username, hashed_password, email, phone, full_name, role))
            self.conn.commit()
            return True
        except pymysql.err.IntegrityError:
            # 用户名已存在
            return False
        except Exception as e:
            print(f"注册用户时出错: {e}")
            return False
    
    def save_face_embedding(self, username, embedding):
        """
        保存用户的人脸特征向量
        :param username: 用户名
        :param embedding: 人脸特征向量（numpy数组）
        :return: 成功返回True，失败返回False
        """
        try:
            # 将numpy数组转换为bytes存储
            embedding_bytes = embedding.tobytes()
            
            sql = "UPDATE users SET face_embedding=%s WHERE username=%s"
            self.cursor.execute(sql, (embedding_bytes, username))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"保存人脸特征时出错: {e}")
            return False
    
    def get_user(self, username):
        """
        获取用户信息
        :param username: 用户名
        :return: 用户信息元组 (id, username, password, face_embedding, created_at, role) 或 None
        """
        try:
            sql = "SELECT id, username, password, face_embedding, created_at, role FROM users WHERE username=%s"
            self.cursor.execute(sql, (username,))
            user = self.cursor.fetchone()
            
            if user and user[3]:  # 如果有人脸特征数据
                # 将bytes转换回numpy数组
                embedding_bytes = user[3]
                embedding = np.frombuffer(embedding_bytes, dtype=np.float32)
                return (user[0], user[1], user[2], embedding, user[4], user[5])
            return user
        except Exception as e:
            print(f"获取用户信息时出错: {e}")
            return None
    
    def get_user_profile(self, username):
        """
        获取用户完整个人资料
        :param username: 用户名
        :return: 用户资料字典或None
        """
        try:
            sql = """
            SELECT id, username, email, phone, full_name, last_login, created_at, role 
            FROM users 
            WHERE username=%s
            """
            self.cursor.execute(sql, (username,))
            user = self.cursor.fetchone()
            
            if user:
                return {
                    'id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'phone': user[3],
                    'full_name': user[4],
                    'last_login': user[5],
                    'created_at': user[6],
                    'role': user[7],
                    'role_name': UserRole.get_role_name(user[7])
                }
            return None
        except Exception as e:
            print(f"获取用户资料时出错: {e}")
            return None
    
    def update_profile(self, username, email=None, phone=None, full_name=None):
        """
        更新用户个人资料
        :param username: 用户名
        :param email: 电子邮件地址
        :param phone: 手机号码
        :param full_name: 姓名
        :return: 成功返回True，失败返回False
        """
        try:
            # 构建更新语句
            update_fields = []
            params = []
            
            if email is not None:
                update_fields.append("email=%s")
                params.append(email)
            
            if phone is not None:
                update_fields.append("phone=%s")
                params.append(phone)
            
            if full_name is not None:
                update_fields.append("full_name=%s")
                params.append(full_name)
            
            if not update_fields:
                return True  # 没有字段需要更新
            
            # 添加用户名参数
            params.append(username)
            
            # 执行更新
            sql = f"UPDATE users SET {', '.join(update_fields)} WHERE username=%s"
            self.cursor.execute(sql, params)
            self.conn.commit()
            return True
        except Exception as e:
            print(f"更新用户资料时出错: {e}")
            return False
    
    def change_password(self, username, current_password, new_password):
        """
        修改用户密码
        :param username: 用户名
        :param current_password: 当前密码
        :param new_password: 新密码
        :return: (成功标志, 消息)，成功返回(True, '密码修改成功')，失败返回(False, 错误信息)
        """
        try:
            # 验证当前密码
            if not self.verify_password(username, current_password):
                return False, "当前密码错误"
            
            # 对新密码进行SHA256加密
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            
            # 更新密码
            sql = "UPDATE users SET password=%s WHERE username=%s"
            self.cursor.execute(sql, (hashed_password, username))
            self.conn.commit()
            return True, "密码修改成功"
        except Exception as e:
            print(f"修改密码时出错: {e}")
            return False, f"修改密码失败: {str(e)}"
    
    def generate_reset_token(self, username_or_email):
        """
        生成密码重置令牌
        :param username_or_email: 用户名或电子邮件
        :return: (成功标志, 令牌或错误信息)
        """
        try:
            # 查找用户
            sql = "SELECT id FROM users WHERE (username=%s OR email=%s)"
            self.cursor.execute(sql, (username_or_email, username_or_email))
            user = self.cursor.fetchone()
            
            if not user:
                return False, "未找到用户"
            
            # 生成令牌
            token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            
            # 设置令牌过期时间（24小时后）
            expires = datetime.datetime.now() + datetime.timedelta(hours=24)
            
            # 保存令牌
            sql = "UPDATE users SET reset_token=%s, reset_token_expires=%s WHERE id=%s"
            self.cursor.execute(sql, (token, expires, user[0]))
            self.conn.commit()
            
            return True, token
        except Exception as e:
            print(f"生成重置令牌时出错: {e}")
            return False, f"生成重置令牌失败: {str(e)}"
    
    def reset_password_with_token(self, token, new_password):
        """
        使用令牌重置密码
        :param token: 重置令牌
        :param new_password: 新密码
        :return: (成功标志, 消息)
        """
        try:
            # 查找有效的令牌
            sql = """
            SELECT id FROM users 
            WHERE reset_token=%s AND reset_token_expires > NOW()
            """
            self.cursor.execute(sql, (token,))
            user = self.cursor.fetchone()
            
            if not user:
                return False, "无效或已过期的重置令牌"
            
            # 对新密码进行SHA256加密
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            
            # 更新密码并清除令牌
            sql = """
            UPDATE users 
            SET password=%s, reset_token=NULL, reset_token_expires=NULL 
            WHERE id=%s
            """
            self.cursor.execute(sql, (hashed_password, user[0]))
            self.conn.commit()
            
            return True, "密码重置成功"
        except Exception as e:
            print(f"重置密码时出错: {e}")
            return False, f"重置密码失败: {str(e)}"
    
    def deactivate_account(self, username, password):
        """
        注销用户账户（永久删除用户数据）
        :param username: 用户名
        :param password: 密码（验证身份）
        :return: (成功标志, 消息)
        """
        try:
            # 验证密码
            if not self.verify_password(username, password):
                return False, "密码错误，无法注销账户"
            
            # 永久删除用户数据
            sql = "DELETE FROM users WHERE username=%s"
            self.cursor.execute(sql, (username,))
            self.conn.commit()
            
            return True, "账户已成功注销并永久删除"
        except Exception as e:
            print(f"注销账户时出错: {e}")
            return False, f"注销账户失败: {str(e)}"
    
    def get_all_users_with_face(self):
        """
        获取所有已注册人脸的用户
        :return: 用户信息列表，每项为元组 (username, id, password, face_embedding)
        """
        try:
            sql = """
            SELECT username, id, password, face_embedding 
            FROM users 
            WHERE face_embedding IS NOT NULL
            """
            self.cursor.execute(sql)
            users = self.cursor.fetchall()
            
            result = []
            for user in users:
                if user[3]:  # 如果有人脸特征数据
                    # 将bytes转换回numpy数组
                    embedding_bytes = user[3]
                    embedding = np.frombuffer(embedding_bytes, dtype=np.float32)
                    result.append((user[0], user[1], user[2], embedding))
            
            return result
        except Exception as e:
            print(f"获取所有用户信息时出错: {e}")
            return []
    
    def update_last_login(self, username):
        """
        更新用户最后登录时间
        :param username: 用户名
        """
        try:
            sql = "UPDATE users SET last_login=NOW() WHERE username=%s"
            self.cursor.execute(sql, (username,))
            self.conn.commit()
        except Exception as e:
            print(f"更新登录时间时出错: {e}")
    
    def verify_password(self, username, password):
        """
        验证用户密码
        :param username: 用户名
        :param password: 密码（明文）
        :return: 验证成功返回True，失败返回False
        """
        try:
            # 获取用户信息
            user = self.get_user(username)
            if not user:
                return False
            
            # 验证密码
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return user[2] == hashed_password
        except Exception as e:
            print(f"验证密码时出错: {e}")
            return False
    
    def user_exists(self, username):
        """
        检查用户是否存在
        :param username: 用户名
        :return: 存在返回True，不存在返回False
        """
        try:
            sql = "SELECT 1 FROM users WHERE username=%s"
            self.cursor.execute(sql, (username,))
            result = self.cursor.fetchone()
            return result is not None
        except Exception as e:
            print(f"检查用户是否存在时出错: {e}")
            return False
    
    def close(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close() 
    
    def update_user_role(self, username, new_role, admin_username):
        """
        更新用户角色
        :param username: 要更新的用户名
        :param new_role: 新角色值
        :param admin_username: 执行操作的管理员用户名
        :return: (成功标志, 消息)
        """
        try:
            # 检查执行操作的管理员权限
            admin_info = self.get_user(admin_username)
            if not admin_info or len(admin_info) < 6:
                return False, "管理员信息获取失败"
            
            admin_role = admin_info[5]
            
            # 获取目标用户信息
            target_user = self.get_user(username)
            if not target_user:
                return False, f"用户 {username} 不存在"
            
            target_role = target_user[5] if len(target_user) >= 6 else UserRole.USER.value
            
            # 权限检查
            if admin_role < UserRole.ADMIN.value:
                return False, "您没有权限执行此操作"
            
            # 只有超级管理员可以管理其他管理员
            if target_role >= UserRole.ADMIN.value and admin_role != UserRole.SUPER_ADMIN.value:
                return False, "只有最高管理员可以修改管理员权限"
            
            # 不能将自己降级
            if username == admin_username:
                return False, "不能修改自己的角色"
            
            # 执行更新
            sql = "UPDATE users SET role=%s WHERE username=%s"
            self.cursor.execute(sql, (new_role, username))
            self.conn.commit()
            
            return True, f"已成功将用户 {username} 的角色更新为 {UserRole.get_role_name(new_role)}"
        except Exception as e:
            print(f"更新用户角色时出错: {e}")
            return False, f"更新用户角色失败: {str(e)}"
    
    def get_users_by_role(self, role=None, admin_username=None):
        """
        获取指定角色的所有用户
        :param role: 角色ID，如果为None则获取所有用户
        :param admin_username: 执行操作的管理员用户名，用于权限检查
        :return: 用户列表或None
        """
        try:
            # 如果指定了管理员用户名，进行权限检查
            if admin_username:
                admin_info = self.get_user(admin_username)
                if not admin_info or len(admin_info) < 6:
                    return None, "管理员信息获取失败"
                
                admin_role = admin_info[5]
                
                # 非管理员不能查看用户列表
                if admin_role < UserRole.ADMIN.value:
                    return None, "您没有权限执行此操作"
                
                # 次级管理员只能查看普通用户
                if admin_role == UserRole.ADMIN.value and (role is None or role >= UserRole.ADMIN.value):
                    role = UserRole.USER.value  # 强制只查看普通用户
            
            # 构建查询
            if role is not None:
                sql = """
                SELECT id, username, email, phone, full_name, last_login, created_at, role 
                FROM users 
                WHERE role=%s
                ORDER BY created_at DESC
                """
                self.cursor.execute(sql, (role,))
            else:
                sql = """
                SELECT id, username, email, phone, full_name, last_login, created_at, role 
                FROM users 
                ORDER BY role DESC, created_at DESC
                """
                self.cursor.execute(sql)
            
            users = self.cursor.fetchall()
            
            # 转换为字典列表
            result = []
            for user in users:
                result.append({
                    'id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'phone': user[3],
                    'full_name': user[4],
                    'last_login': user[5],
                    'created_at': user[6],
                    'role': user[7],
                    'role_name': UserRole.get_role_name(user[7])
                })
            
            return result, "获取成功"
        except Exception as e:
            print(f"获取用户列表时出错: {e}")
            return None, f"获取用户列表失败: {str(e)}"
    
    def delete_user(self, username, admin_username):
        """
        删除用户
        :param username: 要删除的用户名
        :param admin_username: 执行操作的管理员用户名
        :return: (成功标志, 消息)
        """
        try:
            # 检查执行操作的管理员权限
            admin_info = self.get_user(admin_username)
            if not admin_info or len(admin_info) < 6:
                return False, "管理员信息获取失败"
            
            admin_role = admin_info[5]
            
            # 获取目标用户信息
            target_user = self.get_user(username)
            if not target_user:
                return False, f"用户 {username} 不存在"
            
            target_role = target_user[5] if len(target_user) >= 6 else UserRole.USER.value
            
            # 权限检查
            if admin_role < UserRole.ADMIN.value:
                return False, "您没有权限执行此操作"
            
            # 只有超级管理员可以删除管理员
            if target_role >= UserRole.ADMIN.value and admin_role != UserRole.SUPER_ADMIN.value:
                return False, "只有最高管理员可以删除管理员账号"
            
            # 不能删除自己
            if username == admin_username:
                return False, "不能删除自己的账号"
            
            # 执行删除
            sql = "DELETE FROM users WHERE username=%s"
            self.cursor.execute(sql, (username,))
            self.conn.commit()
            
            return True, f"已成功删除用户 {username}"
        except Exception as e:
            print(f"删除用户时出错: {e}")
            return False, f"删除用户失败: {str(e)}"
    
    def reset_user_password(self, username, new_password, admin_username):
        """
        管理员重置用户密码
        :param username: 要重置密码的用户名
        :param new_password: 新密码
        :param admin_username: 执行操作的管理员用户名
        :return: (成功标志, 消息)
        """
        try:
            # 检查执行操作的管理员权限
            admin_info = self.get_user(admin_username)
            if not admin_info or len(admin_info) < 6:
                return False, "管理员信息获取失败"
            
            admin_role = admin_info[5]
            
            # 获取目标用户信息
            target_user = self.get_user(username)
            if not target_user:
                return False, f"用户 {username} 不存在"
            
            target_role = target_user[5] if len(target_user) >= 6 else UserRole.USER.value
            
            # 权限检查
            if admin_role < UserRole.ADMIN.value:
                return False, "您没有权限执行此操作"
            
            # 次级管理员只能重置普通用户密码
            if target_role >= UserRole.ADMIN.value and admin_role != UserRole.SUPER_ADMIN.value:
                return False, "只有最高管理员可以重置管理员密码"
            
            # 对新密码进行SHA256加密
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            
            # 执行更新
            sql = "UPDATE users SET password=%s WHERE username=%s"
            self.cursor.execute(sql, (hashed_password, username))
            self.conn.commit()
            
            return True, f"已成功重置用户 {username} 的密码"
        except Exception as e:
            print(f"重置用户密码时出错: {e}")
            return False, f"重置用户密码失败: {str(e)}" 