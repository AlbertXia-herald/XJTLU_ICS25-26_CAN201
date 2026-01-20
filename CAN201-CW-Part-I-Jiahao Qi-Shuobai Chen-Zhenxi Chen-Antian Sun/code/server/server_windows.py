from socket import *
import json
import os
from os.path import join, getsize
import hashlib
import argparse
from threading import Thread
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math
import shutil
import struct #修正bug5，已正确导入

MAX_PACKET_SIZE = 20480

# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

logger = logging.getLogger('')

#获取file的md5认证加密值
def get_file_md5(filename):
    """
    Get MD5 value for big file
    :param filename:
    :return:
    """
    m = hashlib.md5()
    with open(filename, 'rb') as fid: #bug10: 应以rb形式读取文件内容（MD5基于字节流处理），以r形式读取，会进行字符编码转换
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()


def get_time_based_filename(ext, prefix='', t=None):
    """
    Get a filename based on time
    :param ext: ext name of the filename
    :param prefix: prefix of the filename
    :param t: the specified time if necessary, the default is the current time. Unix timestamp
    :return:
    """
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()
    if t > 4102464500:
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))

#创建一个具有文件和控制台双重输出的日志记录器
def set_logger(logger_name):
    """
    Create a logger
    :param logger_name: 日志名称
    :return: logger
    """
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
    os.makedirs(join('log', logger_file_name), exist_ok=True)#注意，windows中需调整格式 #bug0：未使用基于时间的logger文件名

    # 创建按天轮转的日志处理器
    fh = TimedRotatingFileHandler(filename=join(join('log', logger_file_name), 'application.log'), when='D', interval=1, backupCount=1)#TimedRotatingFileHandler按天轮转（when='D'），1文件/day，保留一个备份
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

#通过parser来保存服务器（ip，port）
def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', action='store', required=False, dest="ip",
                       help="The IP address bind to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listen on. Default is 1379.")
    return parse.parse_args()

#打包函数，将数据处理成STEP格式
def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False) #序列化Json
    j_len = len(j) #计算json长度
    if bin_data is None: #只处理json
        return struct.pack('!II', j_len, 0) + j.encode() #格式：json长度 + 0 + json数据 + b'‘
    else: #包含二进制数据
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data #格式：json长度 + binary长度 + json数据 + 二进制数据

#制作响应pkt（字段+STEP格式数据）
def make_response_packet(operation, status_code, data_type, status_msg, json_data, bin_data=None):
    """
    Make a packet for response
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
    :param status_code: 200 or 400+
    :param data_type: [FILE, DATA, AUTH]
    :param status_msg: A human-readable status massage
    :param json_data
    :param bin_data
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_RESPONSE
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
    json_data[FIELD_TYPE] = data_type
    return make_packet(json_data, bin_data)

#从tcp中获取完整pkt，从中提取出STCP所需的数据format
def get_tcp_packet(conn):
    bin_data = b''#从tcp中获取的全部数据流
    while len(bin_data) < 8: #bug8：头部固定为8bytes（4+4），错误尝试接受16bytes
        data_rec = conn.recv(8) #从connection socket从获取数据流，每次8bytes
        if data_rec == b'':
            return None, None
        else: #bug4：if判定逻辑对易,空串返回none
            time.sleep(0.01)
        bin_data += data_rec
    data = bin_data[:8] #json长度（4bytes）+ binary长度（4bytes）
    bin_data = bin_data[8:] #json data + binary data
    j_len, b_len = struct.unpack('!II', data) #bug5，未正确导入库名
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len) #每一次都从pkt中收取j_len长度的数据
        if data_rec == b'':
            return None, None
        else: #bug6：if判定逻辑对易
            time.sleep(0.01)
        bin_data += data_rec
    j_bin = bin_data[:j_len] #获取json文本的二进制数据

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:] #将json数据切片出去，保留剩余二进制数据
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            return None, None
        else: #bug7：if判定逻辑对易
            time.sleep(0.01)
        bin_data += data_rec
    return json_data, bin_data

#数据处理函数，即操作类型为DATA
def data_process(username, request_operation, json_data, connection_socket):
    """
    Data Process
    :param username:
    :param request_operation:
    :param json_data:
    :param connection_socket:
    :return: None
    """
    global logger
    #处理GET操作
    if request_operation == OP_GET:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'<-- Get data without key.')
            logger.error(f'<-- Field "key" is missing for DATA GET.')
            #Error410，GET字段缺失
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_DATA, f'Field "key" is missing for DATA GET.', {}))
            return
        #GET字段正确
        logger.info(f'--> Get data {json_data[FIELD_KEY]}')
        #路径：data/{username}/{key},检查路径下是否存在文件资源
        if os.path.exists(join('data', username, json_data[FIELD_KEY])) is False:
            #不存在，说明指定的Key不正确，Error404，找不到正确的Key
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_DATA, f'The key {json_data[FIELD_KEY]} is not existing.', {}))
            return
        try:#GET的实际操作
            with open(join('data', username, json_data[FIELD_KEY]), 'r') as fid:
                data_from_file = json.load(fid)
                logger.info(f'<-- Find the data and return to client.')
                #将读取的json数据打包成响应包（GET操作）
                connection_socket.send(
                    make_response_packet(OP_GET, 200, TYPE_DATA, f'OK', data_from_file))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')
    #处理SAVE操作
    if request_operation == OP_SAVE: #bug9:采用小写的op_save，而非正确大写（python大小写分别处理）
        key = str(uuid.uuid4()) #生成一个默认的唯一key（在Client没有提供KEY时为其随机分配）
        if FIELD_KEY in json_data.keys(): #Client已提供，将默认key替换
            key = json_data[FIELD_KEY]
        logger.info(f'--> Save data with key "{key}"')
        if os.path.exists(join('data', username, key)) is True: #若路径下的已有对应的key文件，则无法save，Error402 Key已经存在
            logger.error(f'<-- This key "{key}" is existing.')
            connection_socket.send(make_response_packet(OP_SAVE, 402, TYPE_DATA, f'This key "{key}" is existing.', {}))
            return
        try: #SAVE的实际操作
            with open(join('data', username, key), 'w') as fid:
                json.dump(json_data, fid) #将序列化的json数据写入fid中
                logger.error(f'<-- Data is saved with key "{key}"')
                connection_socket.send(
                    make_response_packet(OP_SAVE, 200, TYPE_DATA, f'Data is saved with key "{key}"', {FIELD_KEY: key}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')
    #处理DELETE操作
    if request_operation == OP_DELETE:
        if FIELD_KEY not in json_data.keys(): #若没有对应key，则无法删除，Error410 字段缺失
            logger.info(f'--> Delete data without any key.')
            logger.error(f'<-- Field "key" is missing for DATA delete.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 410, TYPE_DATA, f'Field "key" is missing for DATA delete.', {}))
            return
        if os.path.exists(join('data', username, json_data[FIELD_KEY])) is False: #若有key字段，但该字段不存在于文件目录，则Error404 无法找到对应key
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 404, TYPE_DATA, f'The "key" {json_data[FIELD_KEY]} is not existing.',
                                     {}))
            return
        try: #DELETE实际操作
            os.remove(join('data', username, json_data[FIELD_KEY])) #删除文件路径下文件remove()
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is deleted.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 200, TYPE_DATA, f'The "key" {json_data[FIELD_KEY]} is deleted.',
                                     {FIELD_KEY: json_data[FIELD_KEY]}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')


def file_process(username, request_operation, json_data, bin_data, connection_socket):
    """
    File Process
    :param username:
    :param request_operation:
    :param json_data:
    :param bin_data:
    :param connection_socket:
    :return:
    """
    global logger
    #Get操作（获取下载计划）
    if request_operation == OP_GET:
        if FIELD_KEY not in json_data.keys(): #字段缺失判定， Error410
            logger.info(f'--> Plan to download file {json_data[FIELD_KEY]}')

            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for DATA GET.', {}))
            return
        logger.info(f'--> Plan to download file with "key" {json_data[FIELD_KEY]}')
        #Error404，未找到对应Key
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False and os.path.exists(
                join('tmp', username, json_data[FIELD_KEY])) is False:
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The key {json_data[FIELD_KEY]} is not existing.', {}))
            return
        #有临时文件但没有完整文件，说明上载不完整，Error 404
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False and os.path.exists(
                join('tmp', username, json_data[FIELD_KEY])) is True:
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not completely uploaded.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE,
                                     f'The key {json_data[FIELD_KEY]} is not completely uploaded.', {}))
            return

        file_path = join('file', username, json_data[FIELD_KEY])
        file_size = getsize(file_path) #文件size
        block_size = MAX_PACKET_SIZE #最大的pkt大小
        total_block = math.ceil(file_size / block_size) #总块数（一共要多少个pkt(s)）
        md5 = get_file_md5(file_path) #对文件内容进行MD5加密
        # Download Plan 制定下载计划
        rval = {
            FIELD_KEY: json_data[FIELD_KEY],
            FIELD_SIZE: file_size,
            FIELD_TOTAL_BLOCK: total_block,
            FIELD_BLOCK_SIZE: block_size,
            FIELD_MD5: md5
        }
        logger.info(f'<-- Plan: file size {file_size}, total block number {FIELD_TOTAL_BLOCK}.')
        connection_socket.send(
            make_response_packet(OP_GET, 200, TYPE_FILE, f'OK. This is the download plan.', rval))
        return
    #SAVE操作（获取上载计划）
    if request_operation == OP_SAVE:
        key = str(uuid.uuid4()) #生成默认唯一Key，用于分配给未指定Key的Client
        if FIELD_KEY in json_data.keys(): #客户已提供key，替换
            key = json_data[FIELD_KEY]
        logger.info(f'--> Plan to save/upload a file with key "{key}"')
        #Error402，该key已有对应文件
        if os.path.exists(join('file', username, key)) is True:
            logger.error(f'<-- This key "{key}" is existing.')
            connection_socket.send(make_response_packet(OP_SAVE, 402, TYPE_FILE, f'This "key" {key} is existing.', {}))
            return
        #bug11：状态码对应错误，此处缺失size字段，应为Error410：字段缺失
        if FIELD_SIZE not in json_data.keys():
            logger.error(f'<-- This file "size" has to be included.')
            connection_socket.send(
                make_response_packet(OP_SAVE, 410, TYPE_FILE, f'This file "size" has to be included', {}))
            return
        file_size = json_data[FIELD_SIZE]
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        try:
            rval = {
                FIELD_KEY: key,
                FIELD_SIZE: file_size,
                FIELD_TOTAL_BLOCK: total_block,
                FIELD_BLOCK_SIZE: block_size,
            }
            # Write a tmp file 将上载计划写入临时文件
            with open(join('tmp', username, key), 'wb+') as fid:
                fid.seek(file_size - 1)
                fid.write(b'\0')

            fid = open(join('tmp', username, key + '.log'), 'w')
            fid.close()
            #向client发送上载计划
            logger.error(f'<-- Upload plan: key {key}, total block number {total_block}, block size {block_size}.')
            connection_socket.send(
                make_response_packet(OP_SAVE, 200, TYPE_FILE, f'This is the upload plan.', rval))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')
    #删除操作
    if request_operation == OP_DELETE:
        if FIELD_KEY not in json_data.keys(): #字段key缺失，Error410
            logger.info(f'--> Delete file without any key.')
            logger.error(f'<-- Field "key" is missing for FILE delete.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for FILE delete.', {}))
            return
        #可简化为and（不存在file文件但存在tep临时文件）
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False:
            if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is True:
                try: #删除tmp临时文件
                    os.remove(join('tmp', username, json_data[FIELD_KEY]))
                    os.remove(join('tmp', username, json_data[FIELD_KEY]) + '.log')
                except Exception as ex:
                    logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')
                logger.error(
                    f'<-- The "key" {json_data[FIELD_KEY]} is not completely uploaded. The tmp files are deleted.')
                connection_socket.send(
                    make_response_packet(OP_GET, 404, TYPE_FILE,
                                         f'The "key" {json_data[FIELD_KEY]} is not completely uploaded. '
                                         f'The tmp files are deleted.',
                                         {}))
                return
            #Error404：没有找到对应key
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is not existing.', {}))
            return
        try: #DELETE实际操作
            os.remove(join('file', username, json_data[FIELD_KEY])) #删除file文件
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is deleted.')
            connection_socket.send(
                make_response_packet(OP_GET, 200, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is deleted.',
                                     {FIELD_KEY: json_data[FIELD_KEY]}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')
    #UPLOAD操作
    if request_operation == OP_UPLOAD:
        if FIELD_KEY not in json_data.keys(): #没有提供Key用于上载，Error410 字段缺失
            logger.info(f'--> Upload file/block without any key.')
            logger.error(f'<-- Field "key" is missing for FILE block uploading.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'Field "key" is missing for FILE uploading.', {}))
            return
        logger.info(f'--> Upload file/block of "key" {json_data[FIELD_KEY]}.')
        #对应key已有文件，说明已经完全上载,Error408 错误操作
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is True:
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is completely uploaded.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 408, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is completely uploaded.', {}))
            return
        #验证是否已通过上载计划申请，若没有上载计划，则无法上载Error 408
        if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is False:
            logger.error(
                f'<-- The "key" {json_data[FIELD_KEY]} is not accepted for uploading.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 408, TYPE_FILE,
                                     f'The "key" {json_data[FIELD_KEY]} is not accepted for uploading.',
                                     {}))
            return
        #缺失必需字段field_block_index
        if FIELD_BLOCK_INDEX not in json_data.keys(): #bug12：filed_block_index为必须字段，必需字段缺失为Error 400
            logger.error(f'<-- The "block_index" is compulsory.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 400, TYPE_FILE, f'The "block_index" is compulsory.', {}))
            return
        file_path = join('tmp', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        block_index = json_data[FIELD_BLOCK_INDEX]
        #块索引超界 Error405
        if block_index >= total_block:
            logger.error(f'<-- The "block_index" exceed the max index.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 405, TYPE_FILE, f'The "block_index" exceed the max index.', {}))
            return
        #块索引字段不合法
        if block_index < 0:
            logger.error(f'<-- The "block_index" should >= 0.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'The "block_index" should >= 0.', {}))
            return
        #最后一块上载，但最后一块的bin_data大小不等于理论剩余的size，故Error406 size不匹配
        if block_index == total_block - 1 and len(bin_data) != file_size - block_size * block_index:
            logger.error(f'<-- The "block_size" is wrong.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 406, TYPE_FILE, f'The "block_size" is wrong.', {}))
            return
        #未到最后一块，且块尺寸不正确， Error406 size不匹配
        if block_index != total_block - 1 and len(bin_data) != block_size:
            logger.error(f'<-- The "block_size" is wrong.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 406, TYPE_FILE, f'The "block_size" is wrong.', {}))
            return
        #写入文件
        with open(file_path, 'rb+') as fid:
            fid.seek(block_size * block_index) #定位到指定偏移量（根据block index定位）
            fid.write(bin_data) #写入数据块
        with open(file_path + '.log', 'a') as fid:
            fid.write(f'{block_index}\n') #记录完成的块索引
        fid = open(file_path + '.log', 'r')
        lines = fid.readlines() #读取所有完成的块索引记录
        fid.close()

        rval = {
            FIELD_KEY: json_data[FIELD_KEY],
            FIELD_BLOCK_INDEX: block_index,
        }
        #已完成上载，记录数==总块数
        if len(set(lines)) == total_block:
            md5 = get_file_md5(file_path) #对文件内容进行MD5加密
            rval[FIELD_MD5] = md5
            os.remove(file_path + '.log') #删除索引块记录日志
            shutil.move(file_path, join('file', username, json_data[FIELD_KEY])) #归档操作：移动文件，将其从tmp文件夹下移动至file文件夹
        #Server向Client发送带有md5的回复
        connection_socket.send(
            make_response_packet(OP_UPLOAD, 200, TYPE_FILE, f'The block {block_index} is uploaded.', rval))
        return
    #下载操作
    if request_operation == OP_DOWNLOAD:
        #key字段缺失，无法下载 Error410
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Download file/block without any key.')
            logger.error(f'<-- Field "key" is missing for FILE block downloading.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for FILE downloading.', {}))
            return
        logger.info(f'--> Download file/block of "key" {json_data[FIELD_KEY]}.')
        #Key字段对应文件不存在，但时存在tmp文件，说明该key对应的文件没有被完整上载，应该先将其上载，才能下载 Error404
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False:
            if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is True:
                logger.error(
                    f'<-- The "key" {json_data[FIELD_KEY]} is not completely uploaded. Please upload it first.')
                connection_socket.send(
                    make_response_packet(OP_GET, 404, TYPE_FILE,
                                         f'The "key" {json_data[FIELD_KEY]} is not completely uploaded. '
                                         f'Please upload it first',
                                         {}))
                return
            #tmp和file都不存在，则不存在key的对应文件，Error404
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is not existing.', {}))
            return
        #没有提供必需的块索引字段，建议同上一样修改为400（原410）
        if FIELD_BLOCK_INDEX not in json_data.keys():
            logger.error(f'<-- The "block_index" is compulsory.')
            connection_socket.send(
                make_response_packet(OP_GET, 400, TYPE_FILE, f'The "block_index" is compulsory.', {}))
            return
        file_path = join('file', username, json_data[FIELD_KEY]) #被下载文件的路径
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        block_index = json_data[FIELD_BLOCK_INDEX]
        #块索引超界 Error405
        if block_index >= total_block:
            logger.error(f'<-- The "block_index" exceed the max index.')
            connection_socket.send( #bug13,块索引超界，错误代码应为405
                make_response_packet(OP_GET, 405, TYPE_FILE, f'The "block_index" exceed the max index.', {}))
            return
        #块索引不合法，Error410
        if block_index < 0:
            logger.error(f'<-- The "block_index" should >= 0.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'The "block_index" should >= 0.', {}))
            return
        #文件读取
        with open(file_path, 'rb') as fid:
            fid.seek(block_size * block_index) #读取偏移(找到对应块索引的位置)
            if block_size * (block_index + 1) < file_size:
                bin_data = fid.read(block_size) #若剩余size多于一个块大小，则读取一整个block_size
            else: #否则读取剩余所有size
                bin_data = fid.read(file_size - block_size * block_index)

            rval = {
                FIELD_BLOCK_INDEX: block_index,
                FIELD_KEY: json_data[FIELD_KEY],
                FIELD_SIZE: len(bin_data)
            }
            logger.info(f'<-- Return block {block_index}({len(bin_data)}bytes) of "key" {json_data[FIELD_KEY]} >= 0.')

            connection_socket.send(make_response_packet(OP_DOWNLOAD, 200, TYPE_FILE,
                                                        'An available block.', rval, bin_data))

#线程目标函数，STEP服务器的主要服务函数
def STEP_service(connection_socket, addr):
    """
    STEP Protocol service
    :param connection_socket:
    :param addr:
    :return: None
    """
    global logger
    while True:
        json_data, bin_data = get_tcp_packet(connection_socket) #从pkt中获取json数据与bin数据
        json_data: dict
        if json_data is None:
            logger.warning('Connection is closed by client.')
            break

        # ACK for "Three Body". If you never read the book "Three Body",
        # just understand the following part as an Echo function. This part is out of the protocol.
        # This is an Easter egg. Aha, this is a very good book.
        #此为彩蛋，若json中字段方向为地球方向，即地球向三体世界发送坐标，则向其回复：“不要回答！不要回答！不要回答！”
        if FIELD_DIRECTION in json_data:
            if json_data[FIELD_DIRECTION] == DIR_EARTH:
                connection_socket.send(
                    make_response_packet('3BODY', 333, 'DANGEROUS', f'DO NOT ANSWER! DO NOT ANSWER! DO NOT ANSWER!', {}))
                continue

        # Check the compulsory fields
        compulsory_fields = [FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE] #操作类型、方向、对象类型

        check_ok = True
        #Error 400判定，是否缺失必填字段
        for _compulsory_fields in compulsory_fields:
            if _compulsory_fields not in list(json_data.keys()):
                connection_socket.send(
                    make_response_packet(OP_ERROR, 400, 'ERROR', f'Compulsory field {_compulsory_fields} is missing.',
                                         {}))
                check_ok = False
                break
        if not check_ok: #check_ok=false时，说明其触发error400，退出函数
            continue

        request_type = json_data[FIELD_TYPE]
        request_operation = json_data[FIELD_OPERATION]
        request_direction = json_data[FIELD_DIRECTION]
        #Eroor407 方向错误
        if request_direction != DIR_REQUEST:
            connection_socket.send(
                make_response_packet(OP_ERROR, 407, 'ERROR', f'Wrong direction. Should be "REQUEST"', {}))
            continue
        #Error408 操作错误
        if request_operation not in [OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN]:
            connection_socket.send(
                make_response_packet(OP_ERROR, 408, 'ERROR', f'Operation {request_operation} is not allowed', {}))
            continue
        #Error409 对象类型错误
        if request_type not in [TYPE_FILE, TYPE_DATA, TYPE_AUTH]:
            connection_socket.send(
                make_response_packet(OP_ERROR, 409, 'ERROR', f'Type {request_type} is not allowed', {}))
            continue
        #处理请求操作为LOGIN（必须是AUTH才能使用该操作）
        if request_operation == OP_LOGIN:
            #Error409 对象类型错误
            if request_type != TYPE_AUTH:
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 409, TYPE_AUTH, f'Type of LOGIN has to be AUTH.', {}))
                continue
            else:#对象类型为AUTH，需要username和password才能登录
                if FIELD_USERNAME not in json_data.keys(): #Error410，缺少用户名字段
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 410, TYPE_AUTH, f'"username" has to be a field for LOGIN', {}))
                    continue
                if FIELD_PASSWORD not in json_data.keys(): #Error410，缺少密码字段
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 410, TYPE_AUTH, f'"password" has to be a field for LOGIN', {}))
                    continue

                # Check the username and password
                #Error407 密码错误
                if hashlib.md5(json_data[FIELD_USERNAME].encode()).hexdigest().lower() != json_data['password'].lower(): #MD5（username）= Password
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 401, TYPE_AUTH, f'"Password error for login.', {}))
                    continue
                else:
                    # Login successful 状态码：200，处理json数据后发回响应pkt（包含token）
                    user_str = f'{json_data[FIELD_USERNAME].replace(".", "_")}.' \
                               f'{get_time_based_filename("login")}' #创建唯一的用户名标识字符串,格式：用户名.时间戳文件名
                    md5_auth_str = hashlib.md5(f'{user_str}kjh20)*(1'.encode()).hexdigest() #对（用户名标识字符串+固定盐值）进行MD5哈希获得加密值
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 200, TYPE_AUTH, f'Login successfully', {
                            FIELD_TOKEN: base64.b64encode(f'{user_str}.{md5_auth_str}'.encode()).decode()
                        }))#token格式：base64（用户名.时间戳.MD5加密认证值）
                    continue

        # If the operation is not LOGIN, check token
        #Error403，缺失token字段
        if FIELD_TOKEN not in json_data.keys():
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'No token.', {}))
            continue

        token = json_data[FIELD_TOKEN]
        token = base64.b64decode(token).decode()
        token: str
        #Error403，token格式错误
        if len(token.split('.')) != 4: #token格式为（用户名.时间戳.MD5加密认证值），长度为4
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'Token format is wrong.', {}))
            continue

        user_str = ".".join(token.split('.')[:3])#
        md5_auth_str = token.split('.')[3]
        #已有用md5（username）同获得的MD5_auth_str校验，不通过则说明Error403，token错误
        if hashlib.md5(f'{user_str}kjh20)*(1'.encode()).hexdigest().lower() != md5_auth_str.lower():
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'Token is wrong.', {}))
            continue

        username = token.split('.')[0]
        #用username创建文件路径
        os.makedirs(join('data', username), exist_ok=True)
        os.makedirs(join('file', username), exist_ok=True)
        os.makedirs(join('tmp', username), exist_ok=True)
        #处理请求
        if request_type == TYPE_DATA:
            data_process(username, request_operation, json_data, connection_socket)
            continue

        if request_type == TYPE_FILE:
            file_process(username, request_operation, json_data, bin_data, connection_socket)
            continue

    connection_socket.close()
    logger.info(f'Connection close. {addr}')

#在新的线程上建立tcp子连接
def tcp_listener(server_ip, server_port):
    """
    TCP listener: liston to a port and [assign TCP sub connections using new threads]
    :param server_ip
    :param server_port
    :return: None
    """
    #主线程开始listen，logger记录server start时间
    global logger
    server_socket = socket(AF_INET, SOCK_STREAM) #bug2：tcp socket传递Message，而非datagram
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) #设置socketopt，允许地址复用
    server_socket.bind((server_ip, int(server_port)))
    server_socket.listen(20)
    logger.info('Server is ready!')
    logger.info(
        f'Start the TCP service, listing {server_port} on IP {"All available" if server_ip == "" else server_ip}')
    while True:
        try:
            connection_socket, addr = server_socket.accept()
            logger.info(f'--> New connection from {addr[0]} on {addr[1]}') #记录client的地址和端口
            th = Thread(target=STEP_service, args=(connection_socket, addr)) #分配子线程
            th.daemon = True #将线程th设置为守护线程（即，主线程退出，所有子线程一并关闭）
            th.start() #bug3: 未启动子线程

        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')

#主函数
def main():
    global logger
    logger = set_logger('STEP')#创建STEP的日志
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port

    os.makedirs('data', exist_ok=True)#创建data文件夹
    os.makedirs('file', exist_ok=True)#创建file文件夹

    tcp_listener(server_ip, server_port)#bug1：函数名调用错误
    # 服务器开始listening，已ready


if __name__ == '__main__':
    main()
