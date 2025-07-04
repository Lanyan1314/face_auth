import cv2
import numpy as np
import torch
import os
import time
import traceback
from facenet_pytorch import MTCNN, InceptionResnetV1
from ..config import MODELS_DIR
from ..utils.logger import get_logger

logger = get_logger('face_detector')

class FaceDetector:
    """
    人脸检测和特征提取类
    使用MTCNN进行人脸检测，InceptionResnetV1进行特征提取
    """
    def __init__(self, device=None):
        """
        初始化人脸检测器
        :param device: 计算设备，None表示自动选择（有GPU用GPU，否则用CPU）
        """
        try:
            # 自动选择设备
            if device is None:
                self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            else:
                self.device = torch.device(device)
            
            logger.info(f"使用设备: {self.device}")
            if self.device.type == 'cuda':
                logger.info(f"GPU设备: {torch.cuda.get_device_name(0)}")
                logger.info(f"可用显存: {torch.cuda.get_device_properties(0).total_memory / 1024**2:.1f}MB")
            
            # 检查本地模型文件
            resnet_model_path = os.path.join(MODELS_DIR, 'modelV1.pt')
            
            # 初始化MTCNN人脸检测器
            logger.info("正在初始化MTCNN人脸检测器...")
            try:
                self.mtcnn = MTCNN(
                    image_size=160,
                    margin=40,
                    keep_all=False,
                    min_face_size=40,
                    thresholds=[0.6, 0.7, 0.7],
                    factor=0.709,
                    post_process=True,
                    device=self.device,
                    select_largest=True
                )
                logger.info("MTCNN模型加载成功")
            except Exception as e:
                error_msg = f"MTCNN模型初始化失败: {str(e)}"
                logger.error(error_msg)
                logger.error(traceback.format_exc())
                raise RuntimeError(error_msg)

            # 初始化InceptionResnetV1特征提取器
            try:
                if not os.path.exists(resnet_model_path):
                    error_msg = f"模型文件不存在: {resnet_model_path}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg)
                    
                logger.info(f"正在从本地加载模型: {resnet_model_path}")
                self.resnet = InceptionResnetV1(pretrained=None).eval().to(self.device)
                state_dict = torch.load(resnet_model_path, map_location=self.device)
                if "logits.weight" in state_dict:
                    del state_dict["logits.weight"]
                    del state_dict["logits.bias"]
                self.resnet.load_state_dict(state_dict)
                logger.info("模型加载成功")
            except Exception as e:
                error_msg = f"特征提取模型初始化失败: {str(e)}"
                logger.error(error_msg)
                logger.error(traceback.format_exc())
                raise RuntimeError(error_msg)

        except Exception as e:
            error_msg = f"人脸检测器初始化失败: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            raise RuntimeError(error_msg)
    
    def detect_face(self, frame):
        """
        检测图像中的人脸
        :param frame: OpenCV格式的图像帧（BGR）
        :return: 检测到的人脸图像张量，如果没有检测到人脸则返回None
        """
        try:
            # 输入验证
            if frame is None:
                logger.error("输入图像为空")
                raise ValueError("输入图像为空")
            
            if not isinstance(frame, np.ndarray):
                logger.error(f"输入图像类型错误，需要numpy.ndarray，实际为{type(frame)}")
                raise ValueError(f"输入图像类型错误，需要numpy.ndarray，实际为{type(frame)}")
            
            if frame.size == 0:
                logger.error("输入图像数据为空")
                raise ValueError("输入图像数据为空")
            
            if len(frame.shape) != 3:
                logger.error(f"输入图像维度错误，需要3维(高度,宽度,通道)，实际为{len(frame.shape)}维")
                raise ValueError(f"输入图像维度错误，需要3维(高度,宽度,通道)，实际为{len(frame.shape)}维")

            logger.debug(f"开始进行人脸检测，图像尺寸: {frame.shape}")
            
            # 图像预处理
            try:
                # 确保图像是BGR格式
                if frame.shape[2] != 3:
                    logger.error(f"图像通道数错误，需要3通道，实际为{frame.shape[2]}通道")
                    raise ValueError(f"图像通道数错误，需要3通道，实际为{frame.shape[2]}通道")
                
                # 转换为RGB
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                logger.debug(f"图像格式转换成功(BGR转RGB)，尺寸: {rgb_frame.shape}")
                
                # 确保图像尺寸合适
                if rgb_frame.shape[0] > 1000 or rgb_frame.shape[1] > 1000:
                    scale = min(1000 / rgb_frame.shape[0], 1000 / rgb_frame.shape[1])
                    new_size = (int(rgb_frame.shape[1] * scale), int(rgb_frame.shape[0] * scale))
                    rgb_frame = cv2.resize(rgb_frame, new_size)
                    logger.debug(f"图像已缩放至 {new_size}")
                
            except Exception as e:
                logger.error(f"图像预处理失败: {str(e)}")
                logger.error(traceback.format_exc())
                raise RuntimeError(f"图像预处理失败: {str(e)}")
            
            # MTCNN人脸检测
            try:
                # 检查MTCNN模型是否已被释放
                if self.mtcnn is None:
                    logger.warning("MTCNN模型已被释放，尝试重新初始化...")
                    if not self.reinitialize():
                        raise RuntimeError("MTCNN模型重新初始化失败")
                    logger.info("MTCNN模型重新初始化成功")
                    
                with torch.no_grad():
                    face = self.mtcnn(rgb_frame)
                    
                if face is None:
                    logger.warning("未检测到人脸，请确保：")
                    logger.warning("1. 人脸在摄像头范围内")
                    logger.warning("2. 光线充足")
                    logger.warning("3. 正面面对摄像头")
                    logger.warning("4. 没有遮挡")
                    raise ValueError("未检测到人脸")
                else:
                    logger.info(f"人脸检测成功，检测到的人脸尺寸: {face.shape}")
                return face
                
            except ValueError as e:
                # 未检测到人脸的情况
                raise
            except RuntimeError as e:
                if "CUDA" in str(e):
                    logger.error(f"GPU内存不足: {str(e)}")
                    # 尝试清理GPU内存
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                        logger.info("已清理GPU缓存")
                    raise RuntimeError(f"GPU内存不足: {str(e)}")
                else:
                    logger.error(f"MTCNN人脸检测运行时错误: {str(e)}")
                    logger.error(traceback.format_exc())
                    raise RuntimeError(f"MTCNN人脸检测运行时错误: {str(e)}")
            except Exception as e:
                logger.error(f"MTCNN人脸检测出错: {str(e)}")
                logger.error(traceback.format_exc())
                raise RuntimeError(f"MTCNN人脸检测出错: {str(e)}")
                
        except ValueError as e:
            # 未检测到人脸的情况
            raise
        except Exception as e:
            logger.error(f"人脸检测过程出现未知错误: {str(e)}")
            logger.error(traceback.format_exc())
            raise RuntimeError(f"人脸检测过程出现未知错误: {str(e)}")
    
    def get_face_embedding(self, frame):
        """
        从图像中提取人脸特征向量
        :param frame: OpenCV格式的图像帧（BGR）
        :return: 人脸特征向量（numpy数组），如果没有检测到人脸则返回None
        """
        try:
            logger.debug("开始提取人脸特征...")
            
            try:
                # 检测人脸
                face = self.detect_face(frame)
            except ValueError as e:
                # 未检测到人脸的情况
                logger.warning(f"特征提取失败：{str(e)}")
                raise
            except Exception as e:
                # 其他人脸检测错误
                logger.error(f"人脸检测失败：{str(e)}")
                raise RuntimeError(f"人脸检测失败：{str(e)}")
            
            # 提取特征向量
            try:
                logger.debug(f"检测到人脸，尺寸: {face.shape}，开始提取特征向量...")
                
                # 检查ResNet模型是否已被释放
                if self.resnet is None:
                    logger.warning("ResNet模型已被释放，尝试重新初始化...")
                    if not self.reinitialize():
                        raise RuntimeError("ResNet模型重新初始化失败")
                    logger.info("ResNet模型重新初始化成功")
                
                with torch.no_grad():
                    # 确保人脸张量在正确的设备上
                    face = face.to(self.device)
                    face_embedding = self.resnet(face.unsqueeze(0))
                embedding = face_embedding.cpu().numpy().flatten().astype(np.float32)
                logger.info(f"人脸特征提取成功，特征向量维度: {embedding.shape}")
                return embedding
                
            except RuntimeError as e:
                if "CUDA" in str(e):
                    logger.error(f"特征提取时GPU内存不足: {str(e)}")
                    raise RuntimeError(f"特征提取时GPU内存不足: {str(e)}")
                else:
                    logger.error(f"特征提取运行时错误: {str(e)}")
                    logger.error(traceback.format_exc())
                    raise RuntimeError(f"特征提取运行时错误: {str(e)}")
            except Exception as e:
                logger.error(f"特征提取过程出错: {str(e)}")
                logger.error(traceback.format_exc())
                raise RuntimeError(f"特征提取过程出错: {str(e)}")
                
        except ValueError as e:
            # 未检测到人脸的情况
            raise
        except Exception as e:
            # 特征提取失败的情况
            raise RuntimeError(f"特征提取失败: {str(e)}")
    
    def compare_faces(self, embedding1, embedding2, threshold=0.6):
        """
        比较两个人脸特征向量的相似度
        :param embedding1: 第一个人脸特征向量
        :param embedding2: 第二个人脸特征向量
        :param threshold: 相似度阈值，低于此值认为是同一个人
        :return: 如果是同一个人则返回True，否则返回False
        """
        try:
            if embedding1 is None or embedding2 is None:
                logger.error("人脸特征向量为空，无法进行比对")
                return False
            
            if not isinstance(embedding1, np.ndarray) or not isinstance(embedding2, np.ndarray):
                logger.error("人脸特征向量类型错误，需要numpy.ndarray")
                return False
            
            if embedding1.shape != embedding2.shape:
                logger.error(f"特征向量维度不匹配: {embedding1.shape} vs {embedding2.shape}")
                return False
            
            distance = np.linalg.norm(embedding1 - embedding2)
            logger.info(f"人脸特征向量距离: {distance:.4f} (阈值: {threshold})")
            
            is_same_person = distance < threshold
            if is_same_person:
                logger.info("人脸匹配成功")
            else:
                logger.info("人脸不匹配")
            
            return is_same_person
            
        except Exception as e:
            logger.error(f"人脸特征比对过程出错: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def release(self):
        """释放资源"""
        try:
            # 释放MTCNN
            if hasattr(self, 'mtcnn'):
                try:
                    del self.mtcnn
                    self.mtcnn = None
                except Exception:
                    pass
            
            # 释放ResNet
            if hasattr(self, 'resnet'):
                try:
                    del self.resnet
                    self.resnet = None
                except Exception:
                    pass
            
            # 清理CUDA缓存
            if torch.cuda.is_available():
                try:
                    torch.cuda.empty_cache()
                except Exception:
                    pass
            
        except Exception:
            pass

    def reinitialize(self):
        """重新初始化模型"""
        try:
            # 初始化MTCNN人脸检测器
            if self.mtcnn is None:
                try:
                    self.mtcnn = MTCNN(
                        image_size=160,
                        margin=40,
                        keep_all=False,
                        min_face_size=40,
                        thresholds=[0.6, 0.7, 0.7],
                        factor=0.709,
                        post_process=True,
                        device=self.device,
                        select_largest=True
                    )
                except Exception:
                    return False

            # 初始化InceptionResnetV1特征提取器
            if self.resnet is None:
                resnet_model_path = os.path.join(MODELS_DIR, 'modelV1.pt')
                try:
                    if not os.path.exists(resnet_model_path):
                        logger.error(f"模型文件不存在: {resnet_model_path}")
                        return False
                        
                    self.resnet = InceptionResnetV1(pretrained=None).eval().to(self.device)
                    state_dict = torch.load(resnet_model_path, map_location=self.device)
                    if "logits.weight" in state_dict:
                        del state_dict["logits.weight"]
                        del state_dict["logits.bias"]
                    self.resnet.load_state_dict(state_dict)
                except Exception:
                    return False
            
            return True
        except Exception:
            return False

    def __del__(self):
        """析构函数"""
        try:
            self.release()
        except Exception:
            pass

    def capture_face_from_camera(self, camera_id=0, max_attempts=10):
        """
        从摄像头捕获人脸
        :param camera_id: 摄像头ID
        :param max_attempts: 最大尝试次数
        :return: 人脸特征向量和人脸图像，如果未检测到人脸则返回(None, None)
        """
        try:
            # 打开摄像头
            cap = cv2.VideoCapture(camera_id)
            if not cap.isOpened():
                logger.error("无法打开摄像头")
                return None, None
            
            embedding = None
            face_image = None
            attempts = 0
            
            while attempts < max_attempts and embedding is None:
                ret, frame = cap.read()
                if not ret:
                    logger.error("无法读取摄像头画面")
                    break
                
                # 检测人脸
                face = self.detect_face(frame)
                if face is not None:
                    # 提取特征向量
                    embedding = self.get_face_embedding(frame)
                    # 保存人脸图像
                    face_image = frame.copy()
                
                attempts += 1
            
            return embedding, face_image
            
        except Exception as e:
            logger.error(f"从摄像头捕获人脸时出错: {str(e)}")
            logger.error(traceback.format_exc())
            return None, None
        finally:
            # 确保摄像头被释放
            if 'cap' in locals() and cap is not None:
                cap.release()
                logger.info("摄像头已释放") 