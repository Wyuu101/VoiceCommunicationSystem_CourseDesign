import socket, pyaudio, numpy as np
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


# ---------------- Hamming(7,4) 编码 ----------------
def hamming_encode_bytes(data: bytes) -> bytes:
    """对字节流进行 Hamming(7,4) 编码"""
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))  # 将字节转换为比特（1位数据）

    # 如果比特数不是4的倍数，进行填充（使得每4个比特为一组）
    if len(bits) % 4 != 0:
        bits = np.concatenate([bits, np.zeros(4 - (len(bits) % 4), dtype=np.uint8)])

    encoded_bits = []  # 存储编码后的比特

    for i in range(0, len(bits), 4):  # 每4个比特为一组进行编码
        d = bits[i:i + 4]  # 获取当前4个数据比特
        # 计算校验位 p1, p2, p3
        p1 = (d[0] + d[1] + d[3]) % 2  # p1 校验位
        p2 = (d[0] + d[2] + d[3]) % 2  # p2 校验位
        p3 = (d[1] + d[2] + d[3]) % 2  # p3 校验位

        # 将数据和校验位按 Hamming(7,4) 编码规则组合
        encoded_bits.extend([p1, p2, d[0], p3, d[1], d[2], d[3]])

    encoded_bits = np.array(encoded_bits, dtype=np.uint8)  # 将比特数组转换为 numpy 数组
    return np.packbits(encoded_bits).tobytes()  # 将编码后的比特转换回字节


# ---------------- A-law 编码 ----------------
def alaw_encode_sample(pcm_val):
    ALAW_MAX = 0x7FFF  # A-law 编码的最大值
    sign = 0x00  # 用于表示符号位
    pcm_val = int(pcm_val)  # 将 pcm 值转换为整数
    if pcm_val < 0:  # 如果是负值
        pcm_val = -pcm_val  # 转为正数
        sign = 0x80  # 设置符号位
    if pcm_val > ALAW_MAX:  # 如果超过最大值
        pcm_val = ALAW_MAX  # 截断到最大值
    if pcm_val >= 256:  # 如果值大于等于 256，进行指数-尾数编码
        exponent = np.floor(np.log2(pcm_val / 256.0)).astype(int)  # 计算指数
        mantissa = (pcm_val >> (exponent + 3)) & 0x0F  # 计算尾数
        aval = (exponent << 4) | mantissa  # 组合成 A-law 编码
    else:  # 小于 256，直接使用 4 位表示
        aval = pcm_val >> 4
    aval ^= 0x55  # 对 A-law 编码值进行掩码（按照标准要求）
    return aval | sign  # 加上符号位


def pcm16_to_alaw(pcm):
    pcm = pcm.astype(np.int32)  # 将 pcm 数据转换为 int32 类型
    out = np.empty_like(pcm, dtype=np.uint8)  # 为 A-law 编码结果分配内存
    for i, sample in enumerate(pcm):  # 遍历每个样本进行 A-law 编码
        out[i] = alaw_encode_sample(sample)
    return out


# ---------------- DES 加密 ----------------
DES_KEY = b'8bytekey'  # DES 加密的密钥
DES_IV = b'12345678'  # DES 加密的 IV（初始化向量）


def encrypt_des_cbc(plaintext: bytes) -> bytes:
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)  # 使用 CBC 模式创建 DES 加密器
    return cipher.encrypt(pad(plaintext, DES.block_size))  # 对数据进行 DES 加密，并填充至块大小


# ---------------- 网络与音频 ----------------
UDP_IP = "127.0.0.1"  # 目标 IP 地址
UDP_PORT = 5005  # 目标端口号

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建 UDP 套接字
p = pyaudio.PyAudio()  # 初始化 PyAudio 库

RATE = 8000  # 采样率 8kHz
CHUNK = 160  # 每次采集 160 个样本，等于 20ms 的音频

stream = p.open(format=pyaudio.paInt16, channels=1, rate=RATE, input=True, frames_per_buffer=CHUNK)  # 打开音频流

print("开始发送音频流...")

while True:
    data = stream.read(CHUNK)  # 从麦克风读取音频数据
    audio_array = np.frombuffer(data, dtype=np.int16)  # 将音频数据转换为 int16 数组
    alaw_data = pcm16_to_alaw(audio_array)  # 将 PCM 数据编码为 A-law
    enc_data = encrypt_des_cbc(alaw_data.tobytes())  # 对 A-law 数据进行 DES 加密
    coded_data = hamming_encode_bytes(enc_data)  # 对加密后的数据进行 Hamming(7,4) 编码
    sock.sendto(coded_data, (UDP_IP, UDP_PORT))  # 发送编码后的数据到目标地址
