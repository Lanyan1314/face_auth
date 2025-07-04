#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
人脸处理工具
提供人脸图像处理功能
"""

import os
import cv2
import numpy as np
import uuid
import traceback
from datetime import datetime
from ..utils.logger import get_logger
from ..config import RESOURCES_DIR

logger = get_logger('face_utils')

def check_face_quality(frame):
    """
    检查人脸图片质量
    :param frame: 摄像头捕获的帧
    :return: (是否合规, 错误信息)
    """
    if frame is None:
        logger.warning("输入图像为None")
        return False, "未检测到人脸图像，请确保摄像头正常工作"
    
    try:
        logger.info(f"开始检查人脸质量，图像尺寸: {frame.shape}")
        
        # 使用OpenCV的Haar级联分类器检测人脸（速度更快，用于初步检查）
        faces = detect_faces(frame)
        
        # 检查faces类型和内容
        logger.info(f"检测到的人脸数据类型: {type(faces)}, 形状: {faces.shape if hasattr(faces, 'shape') else '无形状'}")
        
        # 检查是否检测到人脸
        if isinstance(faces, np.ndarray):
            if faces.size == 0:
                logger.warning("未检测到人脸 (numpy数组为空)")
                return False, "未检测到人脸，请确保：\n1. 面部正对摄像头\n2. 光线充足\n3. 没有遮挡面部的物品（如口罩、墨镜等）"
            face_count = len(faces)
        elif isinstance(faces, tuple):
            # 处理tuple类型的返回值
            if len(faces) == 0 or (len(faces) > 0 and not faces[0]):
                logger.warning("未检测到人脸 (tuple为空)")
                return False, "未检测到人脸，请确保：\n1. 面部正对摄像头\n2. 光线充足\n3. 没有遮挡面部的物品（如口罩、墨镜等）"
            # 如果是非空tuple，尝试获取第一个元素作为人脸
            face_count = len(faces)
            # 转换为列表格式以便后续处理
            faces = list(faces)
        else:
            if not faces:  # 如果是空列表或其他空容器
                logger.warning("未检测到人脸 (列表为空)")
                return False, "未检测到人脸，请确保：\n1. 面部正对摄像头\n2. 光线充足\n3. 没有遮挡面部的物品（如口罩、墨镜等）"
            face_count = len(faces)
        
        # 检查是否检测到多个人脸
        if face_count > 1:
            logger.warning(f"检测到多个人脸: {face_count}")
            return False, f"检测到{face_count}个人脸，请确保画面中只有您一个人的面部"
        
        # 检查人脸大小是否合适
        face = faces[0]
        x, y, w, h = face
        img_height, img_width = frame.shape[:2]
        
        logger.info(f"人脸位置: x={x}, y={y}, w={w}, h={h}, 图像尺寸: {img_width}x{img_height}")
        
        # 计算人脸占图像的比例
        face_ratio = (w * h) / (img_width * img_height)
        
        if face_ratio < 0.05:  # 人脸太小
            logger.warning(f"人脸太小: 比例={face_ratio:.2f}")
            return False, "人脸图像过小，建议：\n1. 请靠近摄像头\n2. 确保面部完全在画面中\n3. 调整摄像头角度"
        
        if face_ratio > 0.8:  # 人脸太大
            logger.warning(f"人脸太大: 比例={face_ratio:.2f}")
            return False, "人脸图像过大，建议：\n1. 请远离摄像头\n2. 调整摄像头角度，使整个面部在画面中"
        
        # 检查人脸是否居中
        face_center_x = x + w/2
        face_center_y = y + h/2
        img_center_x = img_width / 2
        img_center_y = img_height / 2
        
        # 计算人脸中心点与图像中心点的偏移比例
        offset_x = abs(face_center_x - img_center_x) / img_width
        offset_y = abs(face_center_y - img_center_y) / img_height
        
        if offset_x > 0.25 or offset_y > 0.25:  # 人脸偏离中心
            logger.warning(f"人脸未居中: 水平偏移={offset_x:.2f}, 垂直偏移={offset_y:.2f}")
            
            direction = ""
            if face_center_x < img_center_x:
                direction += "向右"
            elif face_center_x > img_center_x:
                direction += "向左"
                
            if face_center_y < img_center_y:
                direction += "向下"
            elif face_center_y > img_center_y:
                direction += "向上"
                
            return False, f"请将面部置于画面中央，建议：\n1. 请{direction}移动面部\n2. 或调整摄像头位置"
        
        # 检查光照条件（简单实现，可以根据需要调整）
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        avg_brightness = cv2.mean(gray)[0]
        
        if avg_brightness < 50:  # 光线太暗
            logger.warning(f"光线太暗: 亮度={avg_brightness:.2f}")
            return False, "环境光线不足，建议：\n1. 请开启更多光源\n2. 面向光源\n3. 避免逆光拍摄"
        
        if avg_brightness > 200:  # 光线太亮
            logger.warning(f"光线太亮: 亮度={avg_brightness:.2f}")
            return False, "环境光线过强，建议：\n1. 请减少光源\n2. 避免阳光直射\n3. 调整面部与光源的角度"
        
        logger.info("人脸图片质量检查通过")
        return True, ""
        
    except Exception as e:
        logger.error(f"检查人脸质量失败: {str(e)}\n{traceback.format_exc()}")
        return False, "人脸质量检测失败，请重试。如果问题持续存在，请联系系统管理员。"

def save_face_image(face_image, username=None):
    """
    保存人脸图像
    :param face_image: 人脸图像（OpenCV格式）
    :param username: 用户名，用于命名文件
    :return: 保存的文件路径或None（如果保存失败）
    """
    try:
        # 创建保存目录
        save_dir = os.path.join(RESOURCES_DIR, 'faces')
        os.makedirs(save_dir, exist_ok=True)
        
        # 生成文件名
        if username:
            filename = f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"
        else:
            filename = f"face_{uuid.uuid4().hex}.jpg"
        
        filepath = os.path.join(save_dir, filename)
        
        # 保存图像
        cv2.imwrite(filepath, face_image)
        logger.info(f"人脸图像已保存: {filepath}")
        
        return filepath
    except Exception as e:
        logger.error(f"保存人脸图像失败: {e}")
        return None

def detect_faces(image, cascade_file=None):
    """
    使用OpenCV的Haar级联分类器检测人脸
    作为MTCNN的备选方案
    :param image: OpenCV格式的图像
    :param cascade_file: 级联分类器文件路径，默认使用OpenCV内置的
    :return: 人脸区域列表 [(x, y, w, h), ...]
    """
    # 如果未指定级联分类器文件，使用OpenCV内置的
    if cascade_file is None:
        cascade_file = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
    
    # 加载级联分类器
    try:
        face_cascade = cv2.CascadeClassifier(cascade_file)
    except Exception as e:
        logger.error(f"加载级联分类器失败: {e}")
        return []
    
    # 转换为灰度图像
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # 检测人脸
    faces = face_cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(30, 30)
    )
    
    return faces

def draw_faces(image, faces):
    """
    在图像上绘制人脸框
    :param image: OpenCV格式的图像
    :param faces: 人脸区域列表 [(x, y, w, h), ...]
    :return: 绘制了人脸框的图像
    """
    image_copy = image.copy()
    
    for (x, y, w, h) in faces:
        cv2.rectangle(image_copy, (x, y), (x+w, y+h), (0, 255, 0), 2)
    
    return image_copy

def crop_face(image, face):
    """
    裁剪人脸区域
    :param image: OpenCV格式的图像
    :param face: 人脸区域 (x, y, w, h)
    :return: 裁剪后的人脸图像
    """
    x, y, w, h = face
    return image[y:y+h, x:x+w]

def normalize_face(face_image, target_size=(160, 160)):
    """
    标准化人脸图像
    :param face_image: 人脸图像
    :param target_size: 目标大小
    :return: 标准化后的人脸图像
    """
    # 调整大小
    face_resized = cv2.resize(face_image, target_size)
    
    # 转换为浮点数并归一化到 [0, 1]
    face_normalized = face_resized.astype(np.float32) / 255.0
    
    return face_normalized 