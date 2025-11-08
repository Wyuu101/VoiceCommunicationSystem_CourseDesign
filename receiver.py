import socket
import pyaudio
import numpy as np
import scipy.signal as signal
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


# ---------------- Hamming(7,4) 解码 ----------------
def hamming_decode_bytes(data: bytes) -> bytes:
    """对字节流进行 Hamming(7,4) 解码并纠错"""
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))  # 将字节转换为比特流

    # 确保比特数是 7 的倍数，否则丢弃剩余部分
    if len(bits) % 7 != 0:
        bits = bits[:len(bits) // 7 * 7]

    decoded_bits = []  # 存储解码后的比特

    for i in range(0, len(bits), 7):  # 每7个比特为一组进行解码
        b = bits[i:i + 7]  # 获取当前的 7 个比特
        p1, p2, d1, p3, d2, d3, d4 = b  # 分离校验位和数据位

        # 检查校验位是否一致，计算错误位位置
        s1 = (p1 + d1 + d2 + d4) % 2  # 校验位 s1
        s2 = (p2 + d1 + d3 + d4) % 2  # 校验位 s2
        s3 = (p3 + d2 + d3 + d4) % 2  # 校验位 s3
        err_pos = s1 + (s2 << 1) + (s3 << 2)  # 错误位的位置（如果为 0，则没有错误）

        if err_pos != 0 and err_pos <= 7:  # 如果有错误且错误位置有效
            b[err_pos - 1] ^= 1  # 纠正错误

        # 取出纠错后的数据位
        _, _, d1, _, d2, d3, d4 = b
        decoded_bits.extend([d1, d2, d3, d4])  # 将数据位添加到结果中

    decoded_bits = np.array(decoded_bits, dtype=np.uint8)  # 将比特数组转换为 numpy 数组
    return np.packbits(decoded_bits).tobytes()  # 将解码后的比特转换为字节


# ---------------- DES 解密 ----------------
DES_KEY = b'8bytekey'  # DES 密钥
DES_IV = b'12345678'  # DES IV


def decrypt_des_cbc(ciphertext: bytes) -> bytes:
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)  # 创建 DES 解密器
    pt = cipher.decrypt(ciphertext)  # 进行 DES 解密
    try:
        pt = unpad(pt, DES.block_size)  # 去除填充
    except ValueError:
        pass  # 如果填充错误，则忽略
    return pt


# ---------------- A-law 解码 ----------------
def alaw_decode_sample(a):
    a = int(a) ^ 0x55  # 解码时反转 A-law 编码中的掩码
    sign = a & 0x80  # 获取符号位
    a &= 0x7F  # 获取数值部分
    exponent = (a >> 4) & 0x07  # 获取指数部分
    mantissa = a & 0x0F  # 获取尾数部分
    if exponent == 0:  # 如果指数部分为 0
        sample = (mantissa << 4) + 8  # 特殊处理
    else:
        sample = ((mantissa << 4) + 0x108) << (exponent - 1)  # 计算样本值
    if sign != 0:  # 如果符号位为负
        sample = -sample
    return np.int16(np.clip(sample, -32768, 32767))  # 确保样本值在 16 位范围内


def alaw_to_pcm16(alaw_bytes: bytes) -> np.ndarray:
    arr = np.frombuffer(alaw_bytes, dtype=np.uint8)  # 将 A-law 数据转换为 uint8 数组
    out = np.empty(len(arr), dtype=np.int16)  # 为解码后的数据分配内存
    for i, a in enumerate(arr):  # 对每个 A-law 数据样本进行解码
        out[i] = alaw_decode_sample(a)
    return out





# ---------------- 音频 ----------------
RATE = 8000  # 采样率
CHANNELS = 1  # 单声道
FORMAT = pyaudio.paInt16  # 16-bit 格式
CHUNK = 160  # 每次读取 160 个样本

# ---------------- 滤波器 ----------------
cutoff_freq = 3400  # 截止频率 (Hz)
nyquist = 0.5 * RATE  # 奈奎斯特频率
normalized_cutoff = cutoff_freq / nyquist  # 归一化截止频率
filter_order = 128  # 滤波器阶数
# 使用 firwin 设计低通滤波器
fir_coeff = signal.firwin(filter_order, normalized_cutoff)




p = pyaudio.PyAudio()
stream_out = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)  # 打开音频输出流

server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 UDP 套接字
server_sock.bind(("0.0.0.0", 5005))  # 绑定到指定端口
print("已开启音频流接收...")

# 初始化滤波器状态
zi = signal.lfilter_zi(fir_coeff, 1.0) * 0

while True:
    data, _ = server_sock.recvfrom(4096)  # 接收数据
    decoded = hamming_decode_bytes(data)  # 对接收到的字节数据进行 Hamming(7,4) 解码
    alaw_enc = decrypt_des_cbc(decoded)  # 解密数据
    pcm = alaw_to_pcm16(alaw_enc)  # 将 A-law 解码为 PCM 数据
    filtered_data, zi = signal.lfilter(fir_coeff, 1.0, pcm.astype(np.float32), zi=zi)
    # 限制数据大小范围
    filtered_data = np.clip(filtered_data, -32768, 32767)
    # 将滤波后的数据转换回字节数据
    filtered_bytes = filtered_data.astype(np.int16).tobytes()
    stream_out.write(filtered_bytes)  # 播放音频
