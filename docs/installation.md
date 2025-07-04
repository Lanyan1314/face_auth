# 安装指南

本文档提供人脸识别双因素登录系统的详细安装步骤。

## 系统要求

- **操作系统**: Windows 10+, macOS 10.14+, 或 Linux (Ubuntu 18.04+)
- **硬件**: 
  - CPU: 建议至少4核
  - RAM: 至少4GB (运行模型时推荐8GB+)
  - 摄像头: 支持720p或以上分辨率的网络摄像头
  - 磁盘空间: 至少500MB (包括模型文件)

## 步骤1: 准备环境

### Python安装

```bash
# 检查Python版本
python --version  # 在Windows上
python3 --version  # 在Linux/macOS上
```

如果没有安装或版本过低，请从[Python官网](https://www.python.org/downloads/)下载并安装。

### MySQL安装

#### Windows
1. 从[MySQL官网](https://dev.mysql.com/downloads/installer/)下载MySQL安装程序
2. 运行安装程序，选择"Server only"或"Custom"安装
3. 按照向导完成安装，记住设置的root密码

#### macOS
```bash
# 使用Homebrew
brew install mysql
brew services start mysql
```

#### Linux (Ubuntu)
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
sudo mysql_secure_installation  # 设置root密码和安全选项
```

## 步骤2: 获取项目代码

```bash
# 使用Git克隆
git clone https://github.com/faceauth/face_auth.git
cd face_auth

# 或者，下载ZIP压缩包并解压
# https://github.com/faceauth/face_auth/archive/refs/heads/main.zip
```

## 步骤3: 创建虚拟环境

```bash
# 创建虚拟环境
python -m venv venv  # Windows
python3 -m venv venv  # Linux/macOS

# 激活虚拟环境
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS
```

## 步骤4: 安装依赖

```bash
# 升级pip
pip install --upgrade pip

# 安装项目依赖
pip install -r requirements.txt
```

### 可能的问题与解决方案

#### PyTorch安装问题
如果安装PyTorch遇到问题，可以尝试从[官方网站](https://pytorch.org/get-started/locally/)获取适合您系统的安装命令。

#### Windows上的OpenCV问题
Windows用户可能需要单独安装OpenCV:
```bash
pip uninstall opencv-python
pip install opencv-python-headless
```

## 步骤5: 配置数据库

### 创建数据库
登录MySQL并创建数据库:

```sql
CREATE DATABASE face_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 修改配置文件
编辑 `src/config.py` 文件，更新数据库连接信息:

```python
# 数据库配置
DB_CONFIG = {
    'host': 'localhost',  # MySQL主机
    'user': 'root',       # 用户名
    'password': '你的密码',  # 修改为你设置的密码
    'db_name': 'face_auth',  # 数据库名
    'port': 3306,
    'charset': 'utf8mb4',
    'connect_timeout': 5,
    'max_retries': 3
}
```

## 步骤6: 运行系统

### 命令行方式
```bash
# 基本运行
python run.py

# 指定数据库配置
python run.py --host localhost --user root --password 你的密码 --db face_auth
```

### 首次运行
首次运行时，系统会自动:
1. 检查环境
2. 创建必要的数据库表

## 故障排除

### 找不到模型文件
如果系统报告找不到人脸检测模型，请按以下步骤操作：

```bash
# 创建模型目录
mkdir -p resources/models

# 将模型文件 modelV1.pt 放入 resources/models 目录
# 注意：模型文件需要单独获取，请联系管理员
```

### 数据库连接问题
确保MySQL服务正在运行，并且用户名和密码正确:

```bash
# 检查MySQL服务状态
# Windows
sc query mysql

# Linux
systemctl status mysql

# macOS
brew services list
```

### 摄像头问题
如果摄像头无法打开:
1. 确认摄像头已正确连接
2. 检查是否已授予应用访问摄像头的权限
3. 确保没有其他应用程序正在使用摄像头

## 下一步

成功安装后，请参考[使用说明](usage.md)了解如何使用系统的各项功能。 