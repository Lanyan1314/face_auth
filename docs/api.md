# API 文档

本文档描述了人脸识别双因素登录系统的主要API接口。

## 认证模块 (auth)

### Authenticator 类

主要的认证管理器，整合密码验证和人脸识别功能。

```python
class Authenticator:
    def __init__(self, db_config, use_cuda=None)
    """
    初始化认证器
    
    参数:
        db_config (dict): 数据库配置字典
        use_cuda (bool, optional): 是否使用CUDA加速
    """
    
    def register_user(self, username, password, full_name=None, email=None)
    """
    注册新用户
    
    参数:
        username (str): 用户名
        password (str): 密码
        full_name (str, optional): 用户全名
        email (str, optional): 电子邮件
        
    返回:
        tuple: (bool, str) - (成功状态, 消息)
    """
    
    def register_face(self, username, face_image)
    """
    为用户注册人脸特征
    
    参数:
        username (str): 用户名
        face_image (numpy.ndarray): OpenCV格式的人脸图像
        
    返回:
        tuple: (bool, str) - (成功状态, 消息)
    """
    
    def verify_password(self, username, password)
    """
    验证用户密码
    
    参数:
        username (str): 用户名
        password (str): 密码
        
    返回:
        tuple: (bool, str) - (成功状态, 消息)
    """
    
    def verify_face(self, face_image, username=None)
    """
    验证用户人脸
    
    参数:
        face_image (numpy.ndarray): OpenCV格式的人脸图像
        username (str, optional): 用户名，如果提供则只与该用户比较
        
    返回:
        tuple: (bool, str, user_info) - (成功状态, 消息, 用户信息)
    """
    
    def login(self, username, password, face_image=None)
    """
    用户登录（支持双因素或单因素认证）
    
    参数:
        username (str): 用户名
        password (str): 密码
        face_image (numpy.ndarray, optional): OpenCV格式的人脸图像
        
    返回:
        tuple: (bool, str, user_info) - (成功状态, 消息, 用户信息)
    """
    
    def is_admin(self)
    """
    检查当前用户是否为管理员
    
    返回:
        bool: 是否为管理员
    """
    
    def get_users_by_role(self, role=None)
    """
    获取指定角色的用户列表
    
    参数:
        role (int, optional): 用户角色ID
        
    返回:
        tuple: (list, str) - (用户列表, 消息)
    """
```

## 数据库模块 (database)

### DBHelper 类

提供数据库操作的封装类。

```python
class DBHelper:
    def __init__(self, config)
    """
    初始化数据库助手
    
    参数:
        config (dict): 数据库配置字典
    """
    
    def create_tables(self)
    """
    创建必要的数据库表
    
    返回:
        bool: 是否成功创建表
    """
    
    def get_user_by_username(self, username)
    """
    通过用户名获取用户信息
    
    参数:
        username (str): 用户名
        
    返回:
        dict: 用户信息字典
    """
    
    def add_user(self, username, password_hash, role=1, full_name=None, email=None)
    """
    添加新用户
    
    参数:
        username (str): 用户名
        password_hash (str): 密码哈希
        role (int, optional): 用户角色，默认为普通用户
        full_name (str, optional): 用户全名
        email (str, optional): 电子邮件
        
    返回:
        tuple: (bool, str) - (成功状态, 消息)
    """
    
    def update_user_face(self, user_id, face_encoding)
    """
    更新用户人脸特征
    
    参数:
        user_id (int): 用户ID
        face_encoding (numpy.ndarray): 人脸特征向量
        
    返回:
        tuple: (bool, str) - (成功状态, 消息)
    """
    
    def get_users(self, role=None)
    """
    获取用户列表
    
    参数:
        role (int, optional): 筛选的用户角色
        
    返回:
        list: 用户信息列表
    """
```

### UserRole 枚举

定义系统中的用户角色。

```python
class UserRole(Enum):
    USER = 1         # 普通用户
    ADMIN = 2        # 管理员
    SUPER_ADMIN = 3  # 超级管理员
```

## 检测模块 (detection)

### FaceDetector 类

封装人脸检测和特征提取功能。

```python
class FaceDetector:
    def __init__(self, use_cuda=None)
    """
    初始化人脸检测器
    
    参数:
        use_cuda (bool, optional): 是否使用CUDA加速
    """
    
    def detect_face(self, image, return_quality=False)
    """
    检测图像中的人脸
    
    参数:
        image (numpy.ndarray): OpenCV格式的图像
        return_quality (bool, optional): 是否返回质量评估
        
    返回:
        tuple: (faces, landmarks, boxes, quality)
    """
    
    def get_face_encoding(self, face_image)
    """
    获取人脸的特征编码
    
    参数:
        face_image (numpy.ndarray): 对齐后的人脸图像
        
    返回:
        numpy.ndarray: 512维特征向量
    """
    
    def compare_faces(self, encoding1, encoding2, threshold=0.7)
    """
    比较两个人脸特征向量的相似度
    
    参数:
        encoding1 (numpy.ndarray): 第一个人脸特征向量
        encoding2 (numpy.ndarray): 第二个人脸特征向量
        threshold (float, optional): 相似度阈值
        
    返回:
        bool: 是否匹配
    """
```

### face_utils 模块

提供人脸图像处理的辅助函数。

```python
def check_face_quality(face_image, landmarks=None)
"""
评估人脸图像质量

参数:
    face_image (numpy.ndarray): 人脸图像
    landmarks (numpy.ndarray, optional): 人脸关键点

返回:
    tuple: (float, dict) - (总体质量得分, 各项指标)
"""

def align_face(image, landmarks)
"""
根据关键点对齐人脸

参数:
    image (numpy.ndarray): 原始图像
    landmarks (numpy.ndarray): 人脸关键点

返回:
    numpy.ndarray: 对齐后的人脸图像
"""
```

## 工具模块 (utils)

### logger 模块

提供统一的日志记录功能。

```python
def setup_logger()
"""
设置日志系统

返回:
    logging.Logger: 全局日志记录器
"""

def get_logger(name)
"""
获取命名的日志记录器

参数:
    name (str): 日志记录器名称
    
返回:
    logging.Logger: 日志记录器实例
"""
```

### validators 模块

提供数据验证函数。

```python
def validate_username(username)
"""
验证用户名

参数:
    username (str): 用户名
    
返回:
    tuple: (bool, str) - (是否有效, 消息)
"""

def validate_password(password)
"""
验证密码

参数:
    password (str): 密码
    
返回:
    tuple: (bool, str) - (是否有效, 消息)
"""

def validate_email(email)
"""
验证电子邮件

参数:
    email (str): 电子邮件
    
返回:
    tuple: (bool, str) - (是否有效, 消息)
"""

def validate_login_form(username, password)
"""
验证登录表单

参数:
    username (str): 用户名
    password (str): 密码
    
返回:
    tuple: (bool, str) - (是否有效, 消息)
"""

def validate_register_form(username, password, confirm_password, email=None)
"""
验证注册表单

参数:
    username (str): 用户名
    password (str): 密码
    confirm_password (str): 确认密码
    email (str, optional): 电子邮件
    
返回:
    tuple: (bool, str) - (是否有效, 消息)
"""
```

## 视图模块 (views)

主要的界面类包括：

- `LoginWindow`: 登录界面
- `RegisterWindow`: 注册界面
- `MainWindow`: 主界面
- `AdminWindow`: 管理后台界面

以及组件类：

- `MessageBox`: 消息框组件

注意：视图模块主要是UI实现，不作为API使用，因此不详细列出方法。 