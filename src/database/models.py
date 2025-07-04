#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据模型
定义数据库表结构
"""

import hashlib
import time
import numpy as np
from enum import Enum
from ..utils.logger import get_logger

logger = get_logger('models')

class UserRole(Enum):
    """用户角色枚举"""
    SUPER_ADMIN = 3  # 最高管理员
    ADMIN = 2        # 次级管理员
    USER = 1         # 普通用户
    
    @classmethod
    def get_role_name(cls, role_id):
        """
        根据角色ID获取角色名称
        :param role_id: 角色ID
        :return: 角色名称
        """
        role_names = {
            cls.SUPER_ADMIN.value: "最高管理员",
            cls.ADMIN.value: "管理员",
            cls.USER.value: "普通用户"
        }
        return role_names.get(role_id, "未知角色")

class User:
    """用户模型"""
    
    def __init__(self, id=None, username=None, password=None, face_embedding=None, created_at=None, role=UserRole.USER.value):
        """
        初始化用户模型
        :param id: 用户ID
        :param username: 用户名
        :param password: 密码（已加密）
        :param face_embedding: 人脸特征向量
        :param created_at: 创建时间
        :param role: 用户角色，默认为普通用户
        """
        self.id = id
        self.username = username
        self.password = password
        self.face_embedding = face_embedding
        self.created_at = created_at or int(time.time())
        self.role = role
    
    @staticmethod
    def hash_password(password):
        """
        对密码进行哈希加密
        :param password: 原始密码
        :return: 加密后的密码
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password):
        """
        验证密码
        :param password: 待验证的密码
        :return: 验证成功返回True，失败返回False
        """
        hashed_password = self.hash_password(password)
        return hashed_password == self.password
    
    def set_face_embedding(self, embedding):
        """
        设置人脸特征向量
        :param embedding: numpy数组形式的特征向量
        """
        if isinstance(embedding, np.ndarray):
            self.face_embedding = embedding
        else:
            logger.warning("人脸特征向量必须是numpy数组")
    
    def has_face_registered(self):
        """
        检查用户是否已注册人脸
        :return: 已注册返回True，否则返回False
        """
        return self.face_embedding is not None
    
    def is_admin(self):
        """
        检查用户是否为管理员（包括最高管理员和次级管理员）
        :return: 是管理员返回True，否则返回False
        """
        return self.role >= UserRole.ADMIN.value
    
    def is_super_admin(self):
        """
        检查用户是否为最高管理员
        :return: 是最高管理员返回True，否则返回False
        """
        return self.role == UserRole.SUPER_ADMIN.value
    
    @classmethod
    def from_tuple(cls, data_tuple):
        """
        从数据库查询结果创建用户对象
        :param data_tuple: 数据库查询结果元组 (id, username, password, face_embedding, created_at, role)
        :return: 用户对象
        """
        if not data_tuple or len(data_tuple) < 3:
            return None
        
        id, username, password = data_tuple[0:3]
        
        # 处理人脸特征向量
        face_embedding = None
        if len(data_tuple) > 3 and data_tuple[3] is not None:
            try:
                face_embedding = np.frombuffer(data_tuple[3], dtype=np.float32)
            except Exception as e:
                logger.error(f"解析人脸特征向量出错: {e}")
        
        # 处理创建时间
        created_at = None
        if len(data_tuple) > 4:
            created_at = data_tuple[4]
        
        # 处理用户角色
        role = UserRole.USER.value
        if len(data_tuple) > 5:
            role = data_tuple[5]
        
        return cls(id, username, password, face_embedding, created_at, role)
    
    def to_dict(self):
        """
        将用户对象转换为字典
        :return: 用户字典
        """
        user_dict = {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at,
            'has_face': self.has_face_registered(),
            'role': self.role,
            'role_name': UserRole.get_role_name(self.role)
        }
        return user_dict 