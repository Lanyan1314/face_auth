#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
摄像头组件
封装摄像头功能
"""

import cv2
import numpy as np
from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout
from PyQt5.QtGui import QImage, QPixmap, QPainter
from PyQt5.QtCore import Qt, QTimer, pyqtSignal

from ...utils.logger import get_logger
from ...detection.face_detector import FaceDetector

logger = get_logger('camera_widget')

class CameraWidget(QWidget):
    """摄像头组件"""
    
    # 自定义信号
    frame_captured = pyqtSignal(np.ndarray)  # 捕获到一帧图像
    face_detected = pyqtSignal(np.ndarray)   # 检测到人脸
    
    def __init__(self, parent=None, camera_id=0, fps=10, width=320, height=240):
        """
        初始化摄像头组件
        :param parent: 父窗口
        :param camera_id: 摄像头ID
        :param fps: 帧率
        :param width: 宽度
        :param height: 高度
        """
        super().__init__(parent)
        
        self.camera_id = camera_id
        self.fps = fps
        self.width = width
        self.height = height
        
        # 初始化摄像头
        self.camera = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_frame)
        
        # 初始化人脸检测器
        try:
            self.face_detector = FaceDetector()
            logger.info("人脸检测器初始化成功")
        except Exception as e:
            logger.error(f"人脸检测器初始化失败: {e}")
            self.face_detector = None
        
        # 初始化UI
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        # 创建布局
        layout = QVBoxLayout()
        
        # 创建标签
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setMinimumSize(self.width, self.height)
        self.image_label.setStyleSheet("border: 1px solid #cccccc;")
        
        # 添加标签到布局
        layout.addWidget(self.image_label)
        
        # 设置布局
        self.setLayout(layout)
    
    def open_camera(self, camera_id=0):
        """打开摄像头"""
        try:
            self.camera = cv2.VideoCapture(camera_id)
            if not self.camera.isOpened():
                logger.error("无法打开摄像头")
                return False
                
            # 设置摄像头分辨率
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            
            # 启动定时器，定期更新画面
            self.timer.start(30)  # 30ms更新一次
            return True
        except Exception as e:
            logger.error(f"打开摄像头时出错: {str(e)}")
            return False
    
    def update_frame(self):
        """更新摄像头画面"""
        if self.camera is None:
            return
        
        ret, frame = self.camera.read()
        if not ret:
            logger.error("无法读取摄像头画面")
            return
        
        # 发送帧捕获信号
        self.frame_captured.emit(frame)
        
        # 如果人脸检测器可用，进行人脸检测
        if self.face_detector is not None:
            try:
                # 使用MTCNN进行人脸检测
                face_tensor = self.face_detector.detect_face(frame)
                if face_tensor is not None:
                    # 将PyTorch张量转换为numpy数组
                    face_array = face_tensor.cpu().numpy()
                    face_array = (face_array * 255).astype(np.uint8)
                    face_array = np.transpose(face_array, (1, 2, 0))  # 调整通道顺序
            
            # 发送人脸检测信号
                    self.face_detected.emit(face_array)
            
                    # 在原图上绘制人脸框
                    h, w = frame.shape[:2]
                    cv2.rectangle(frame, (0, 0), (w, h), (0, 255, 0), 2)
                    
            except Exception as e:
                logger.error(f"人脸检测过程出错: {e}")
        
        # 转换图像格式
        rgb_image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb_image.shape
        bytes_per_line = ch * w
        
        # 创建QImage
        qt_image = QImage(rgb_image.data, w, h, bytes_per_line, QImage.Format_RGB888)
        self.current_frame = qt_image
        
        # 显示图像
        pixmap = QPixmap.fromImage(qt_image)
        self.image_label.setPixmap(pixmap.scaled(
            self.image_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        ))
    
    def get_current_frame(self):
        """获取当前帧"""
        if self.current_frame is None:
            return None
        
        # 将QImage转换为numpy数组
        try:
            width = self.current_frame.width()
            height = self.current_frame.height()
            ptr = self.current_frame.bits()
            ptr.setsize(height * width * 4)
            arr = np.frombuffer(ptr, np.uint8).reshape((height, width, 4))
            # 转换RGBA为BGR格式
            bgr_image = cv2.cvtColor(arr, cv2.COLOR_RGBA2BGR)
            return bgr_image
        except Exception as e:
            logger.error(f"图像格式转换失败: {str(e)}")
            return None
        
    def cleanup(self):
        """清理摄像头资源"""
        if self.camera is not None:
            self.timer.stop()
            self.camera.release()
            self.camera = None
        self.current_frame = None
    
    def is_camera_open(self):
        """检查摄像头是否打开"""
        return self.camera is not None and self.camera.isOpened()
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        self.cleanup()
        if self.face_detector is not None:
            self.face_detector.release()
        event.accept()