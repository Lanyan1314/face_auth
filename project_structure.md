# 人脸识别与密码双因素登录系统 - 项目结构

```
face_auth/
│
├── src/                           # 源代码目录
│   ├── __init__.py               # 包初始化文件
│   ├── main.py                   # 主程序入口
│   ├── config.py                 # 配置文件
│   │
│   ├── utils/                    # 工具函数
│   │   ├── __init__.py
│   │   ├── logger.py             # 日志工具
│   │   └── validators.py         # 数据验证工具
│   │
│   ├── auth/                     # 认证相关模块
│   │   ├── __init__.py
│   │   └── authenticator.py      # 认证类（整合密码验证和人脸识别）
│   │
│   ├── database/                 # 数据库相关模块
│   │   ├── __init__.py
│   │   ├── db_helper.py          # 数据库操作类
│   │   └── models.py             # 数据模型和角色定义
│   │
│   ├── detection/                # 人脸检测相关模块
│   │   ├── __init__.py
│   │   ├── face_detector.py      # 人脸检测与特征提取
│   │   └── face_utils.py         # 人脸图像处理工具
│   │
│   └── views/                    # 界面相关模块
│       ├── __init__.py
│       ├── login_window.py       # 登录窗口
│       ├── register_window.py    # 注册窗口
│       ├── main_window.py        # 主窗口
│       ├── admin_window.py       # 管理员窗口
│       └── components/           # UI组件
│           ├── __init__.py
│           ├── camera_widget.py  # 摄像头组件（未使用）
│           └── message_box.py    # 消息框组件
│
├── resources/                     # 资源文件目录
│   ├── icons/                    # 图标资源
│   ├── styles/                   # 样式表
│   └── models/                   # 预训练模型
│
├── logs/                          # 日志目录
│
├── docs/                          # 文档目录
│   ├── installation.md           # 安装指南
│   ├── usage.md                  # 使用说明
│   ├── api.md                    # API文档
│   └── admin_system.md           # 管理系统说明
│
├── .gitignore                     # Git忽略文件
├── LICENSE                        # MIT许可证文件
├── README.md                      # 项目说明文件
├── project_structure.md           # 本文件
├── requirements.txt               # 依赖列表
├── setup.py                       # 安装配置
└── run.py                         # 启动脚本
```

## 模块职责

### 1. auth 模块
负责用户认证，整合密码验证和人脸识别功能，提供双因素认证服务。

### 2. database 模块
负责数据存储和检索，包括用户信息和人脸特征向量的存储与管理。

### 3. detection 模块
负责人脸检测、对齐和特征提取，以及人脸质量评估。

### 4. views 模块
提供图形用户界面，包括登录、注册、主界面和管理后台。

### 5. utils 模块
提供辅助功能，如日志记录、数据验证等通用工具函数。

## 核心文件功能

### 认证和安全
- **authenticator.py**: 统一的认证管理器，处理登录和验证逻辑
- **models.py**: 定义用户角色和权限系统
- **db_helper.py**: 安全的数据库操作，包含密码加密和令牌生成

### 人脸识别
- **face_detector.py**: 封装MTCNN和InceptionResnetV1模型，提供人脸检测和特征提取
- **face_utils.py**: 人脸图像处理工具，如质量评估、预处理等

### 界面
- **login_window.py**: 登录窗口，提供账号密码和人脸识别登录
- **register_window.py**: 注册窗口，用于新用户注册和人脸采集
- **main_window.py**: 登录成功后的主界面
- **admin_window.py**: 管理员后台，用于用户管理和系统设置 