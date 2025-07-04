# 人脸识别双因素登录系统

基于 PyTorch 和 PyQt5 的人脸识别和密码双因素登录系统，提供安全便捷的身份验证解决方案。

有任何问题可联系管理员AShu，发送验证消息时候请备注来意，否则不允处理！
![img.png](img.png)

## 主要特性

- **双因素认证**：账号密码和人脸识别相结合，增强安全性
- **灵活登录方式**：支持单独使用账号密码或人脸识别登录
- **用户管理功能**：个人资料管理、密码修改、重置与账户注销
- **管理员系统**：用户管理、权限控制和系统监控
- **安全存储**：密码通过 SHA-256 加密存储

## 技术栈

- Python 
- PyQt5 (GUI界面)
- PyTorch & MTCNN (人脸检测与识别)
- OpenCV (图像处理)
- MySQL (数据存储)

### 前提条件

- Python
- MySQL
- 网络摄像头

## 快速开始

### 前提条件

- Python
- MySQL
- 网络摄像头

### 安装

1. **克隆项目**
   ```bash
   git clone https://github.com/yourusername/face_auth.git
   cd face_auth
   ```

2. **创建虚拟环境**
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/macOS
   source venv/bin/activate
   ```

3. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

4. **配置数据库**
   - 创建数据库: `CREATE DATABASE face_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
   - 在 `src/config.py` 中修改数据库连接信息

### 运行

```bash
# 基本运行
python run.py

# 指定数据库配置
python run.py --host localhost --user root --password yourpassword --db face_auth
```

## 使用指南

### 新用户注册

1. 点击登录界面的"注册新用户"按钮
2. 填写必要信息并创建账号
3. 完成人脸录入

### 登录

- **密码登录**：输入账号和密码，点击"账号密码登录"
- **人脸登录**：点击"开启摄像头"，然后点击"人脸识别登录"

### 管理员功能

1. 以管理员身份登录
2. 在登录成功后选择"进入管理后台"
3. 管理用户、重置密码、修改权限

## 项目结构

```
face_auth/
├── src/                           # 源代码
│   ├── auth/                     # 认证模块
│   ├── database/                 # 数据库操作
│   ├── detection/                # 人脸检测
│   ├── utils/                    # 工具函数
│   └── views/                    # UI界面
├── resources/                     # 资源文件
├── docs/                          # 文档
└── run.py                         # 启动脚本
```

## 文档

- [安装指南](docs/installation.md) - 详细安装步骤
- [使用说明](docs/usage.md) - 详细使用说明
- [API文档](docs/api.md) - 开发API参考
- [管理系统](docs/admin_system.md) - 管理员功能

## 许可证

[MIT](LICENSE)

## 给作者来杯咖啡
开源不易，如果此项目对您有帮助，可以考虑请AShu一杯咖啡吗

支付宝
![img_1.png](img_1.png)