from socket import *
import json
import os
from os.path import join
import hashlib
import argparse
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import struct

# Const Value
MAX_PACKET_SIZE = 20480
server_port = 1379
server_ip = None #'127.0.0.1'
USERNAME = None #"XiaXi"
token = "WGlhWGkuMjAyNTExMDYyMDI5NTIubG9naW4uYTZhYWEzNDAyODU3MzBmNjQyMGU5YmVlOTliNWYwYTI="
FILE = None #'data/DSC05618.jpg'
UPLOAD_BLOCK = 0
UPLOAD_RESULT = []


OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

logger = logging.getLogger('')
#通过parse来保存所需信息（ip，id，file_path）
def _argparse():
    parser = argparse.ArgumentParser(description='--server_ip [ip] --id [id] --f <path to a file>')
    parser.add_argument("--server_ip", default='', required=True, dest="ip",help="The IP address bind to the server.")
    parser.add_argument("--id", required=True, help="The username of Client.")
    parser.add_argument("--f", required=True, help='path of file')

    return parser.parse_args()

#获取file的md5认证加密值
def get_file_md5(filename):
    m = hashlib.md5()
    with open(filename, 'rb') as fid: #bug14: 应以rb形式读取文件内容（MD5基于字节流处理），以r形式读取，会进行字符编码转换
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()

def get_time_based_filename(ext, prefix='', t=None):
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()
    if t > 4102464500:
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))

#创建一个具有文件和控制台双重输出的日志记录器
def set_logger(logger_name):
    logger_ = logging.getLogger(logger_name)  # 不加名称设置root logger
    logger_.setLevel(logging.INFO)#记录INFO及以上级别的日志

    formatter = logging.Formatter(
        '\033[0;34m%s\033[0m' % '%(asctime)s-%(name)s[%(levelname)s] %(message)s @ %(filename)s[%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S')
    # 蓝色文本，
    # 格式：时间、logger名称、日志级别、消息、文件名和行号，
    # 时间格式： 年-月-日 时:分:秒

    # --> LOG FILE
    #创建日志目录（在 log/{logger_file_name}/目录下存储日志文件）
    logger_file_name = get_time_based_filename('log')
    os.makedirs(join('../client/log', logger_file_name), exist_ok=True)#注意，windows中需调整格式 #bug0：未使用基于时间的logger文件名

    # 创建按天轮转的日志处理器
    fh = TimedRotatingFileHandler(filename=join(join('../client/log', logger_file_name), 'application.log'), when='D', interval=1, backupCount=1)#TimedRotatingFileHandler按天轮转（when='D'），1文件/day，保留一个备份
    fh.setFormatter(formatter)

    fh.setLevel(logging.INFO)

    # --> SCREEN DISPLAY
    #输出到控制台，格式与日志记录器相同
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger_.propagate = False #阻止日志传递给父Logger
    logger_.addHandler(ch) #添加控制台处理器
    logger_.addHandler(fh) #添加文件处理器
    return logger_

def realtime_updating(curr_block, total_block, start_time):
    # 实时更新块上载的进度
    progress = ''
    uploaded = int(curr_block / total_block * 10) + 1
    for _ in range(uploaded * 2):
        progress += '='
    for _ in range(20 - uploaded * 2):
        progress += '-'
    speed = curr_block * MAX_PACKET_SIZE / (time.time() - start_time) / 1024 / 1024
    eta = (total_block - (curr_block + 1)) / (curr_block / (time.time() - start_time)) if curr_block != 0 else 0
    logger.info(
        f'\rUploading block: {curr_block}/{total_block} [{progress}]{(curr_block + 1) / total_block * 100:.1f}% Avg.Speed: {speed:.1f}MB/s ETA: {eta:.2f}s')
    return

#打包函数，将数据处理成STEP格式
def make_packet(json_data, bin_data=None):
    j = json.dumps(dict(json_data), ensure_ascii=False) #序列化Json
    j_len = len(j) #计算json长度
    if bin_data is None: #只处理json
        return struct.pack('!II', j_len, 0) + j.encode() #格式：json长度 + 0 + json数据 + b'‘
    else: #包含二进制数据
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data #格式：json长度 + binary长度 + json数据 + 二进制数据

#制作常规请求pkt（字段+STEP格式数据）
def make_request_packet(operation, data_type, json_data, bin_data=None):
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_TYPE] = data_type
    #向json_data中填入direction,token
    if FIELD_DIRECTION not in json_data:
        json_data[FIELD_DIRECTION] = 'REQUEST'
    json_data[FIELD_TOKEN] = token
    return make_packet(json_data, bin_data)

#从tcp中获取完整pkt，从中提取出STCP所需的数据format
def get_tcp_packet(raw_data):
    # make sure raw message is not empty
    if len(raw_data) > 8:
        # [:4]: json_len, [4:8] bin_len
        # [8:8+json_len]: json data
        # [8+json_len:]: bin data
        json_len, bin_len = struct.unpack('!II', raw_data[:8])
        json_data = json.loads(raw_data[8:8 + json_len].decode())
        bin_data = raw_data[8 + json_len:]
        return json_data, bin_data

    logger.info(f'Warning: received message length is {len(raw_data)}, which means the response message is not entire!')
    return None, None

#制作login请求包，接收Server给予的token
def user_login(client, username):
    global token
    password = hashlib.md5(username.encode()).hexdigest()
    user_login_json = {FIELD_USERNAME: username, FIELD_PASSWORD: password}
    packet = make_request_packet(OP_LOGIN, TYPE_AUTH, user_login_json)
    json_data, bin_data = client.send_request(packet)

    if json_data and FIELD_TOKEN in json_data:
        client.token = json_data[FIELD_TOKEN]
        logger.info(f'Login Successful, token: {client.token}')
        return True
    else:
        logger.warning('Login Failed, the token is not founded!!')
        return False

#制作save请求包，接收Server给予的Upload Plan
def save_file(client, file, file_size):
    #从socket中取得上载计划
    packet = make_request_packet(OP_SAVE, TYPE_FILE, {FIELD_SIZE: file_size, FIELD_KEY: os.path.basename(file)})
    upload_plan, _ = client.send_request(packet)

    #检查status
    if upload_plan.get(FIELD_STATUS) == 402:
        logger.error(f'[STATUS 402]!! File {file} already exists!')
        return None

    logger.info(f'Upload Plan: dividing file into {upload_plan.get(FIELD_TOTAL_BLOCK)} blocks ,which block size is {upload_plan.get(FIELD_BLOCK_SIZE)} and key is "{upload_plan.get(FIELD_KEY)}" .')
    return upload_plan
#文件上载函数，将单一文件分块传递给
def upload_file(client, file, upload_plan):
    total_block = upload_plan.get(FIELD_TOTAL_BLOCK)
    key = upload_plan.get(FIELD_KEY)
    start_time = time.time()
    with open (file, 'rb') as f:
        for i in range(total_block):
            bin_data = f.read(MAX_PACKET_SIZE) #文件的传输数据，binary形式
            #可进行缺块、乱块实验
            json_data = {FIELD_KEY:key, FIELD_BLOCK_INDEX: i}
            packet = make_request_packet(OP_UPLOAD, TYPE_FILE, json_data, bin_data) #将文件传输数据与json描述打包
            upload_data, _ = client.send_request(packet)
            logger.info(f'{FIELD_STATUS_MSG}')
            UPLOAD_RESULT.append(upload_data)
            #实时更新每次传输的信息
            realtime_updating(i,total_block,start_time)

    end_time = time.time()
    logger.info(f'uploading cost time: {(end_time - start_time):.5f} seconds')

def make_socket(ip=None, port=None):
    target_ip = ip if ip else server_ip
    target_port = port if port else server_port

    if not target_ip:
        raise ValueError("Server IP not specified")

    client_sock = socket(AF_INET,SOCK_STREAM)
    client_sock.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
    client_sock.connect((target_ip, target_port))
    return client_sock

class STEPClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.token = None

    def connect(self):
        """建立连接"""
        if self.socket:
            self.socket.close()

        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.connect((self.server_ip, self.server_port))
        return self.socket

    def send_request(self, packet):
        """发送请求并接收响应"""
        self.socket.send(packet)
        response = self.socket.recv(MAX_PACKET_SIZE)
        return get_tcp_packet(response)

    def close(self):
        """关闭连接"""
        if self.socket:
            self.socket.close()
        self.socket = None


def main():
    global logger, server_ip, USERNAME, FILE
    # 解析参数
    args = _argparse()
    server_ip = args.ip
    USERNAME = args.id
    FILE = args.f

    # 验证文件存在
    if not os.path.exists(FILE):
        logger.error(f"File not found: {FILE}")
        return

    logger = set_logger('STEP_Client')

    client = STEPClient(server_ip, server_port)

    try:
        # 连接服务器
        client.connect()

        # 执行操作
        if user_login(client, USERNAME):
            upload_plan = save_file(client, FILE, os.path.getsize(FILE))
            if upload_plan:
                upload_file(client, FILE, upload_plan)

    except Exception as e:
        logger.error(f"Client error: {e}")
    finally:
        client.close()


if __name__ =='__main__':
    main()