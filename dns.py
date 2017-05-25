import socket
import struct
import sys
import time
from pprint import pprint


class package:
    def __init__(self, data=None):
        self.data = data
        if data:

            # Header
            self.ID = data[0:2]
            self.QR = (data[2] & 0x80) >> 7  # 0查询 1响应
            self.Opcode = (data[2] & 0x78) >> 3
            self.AA = (data[2] & 0x04) >> 2
            self.TC = (data[2] & 0x02) >> 1
            self.RD = (data[2] & 0x01)
            self.RA = (data[3] & 0x80) >> 7
            self.Z = data[3] & 0x70
            self.RCODE = (data[3] & 0x0F)
            self.QDCOUNT = data[4:6]
            self.ANCOUNT = data[6:8]
            self.NSCOUNT = data[8:10]
            self.ARCOUNT = data[10:12]

            # Question
            i = 12
            self.domainList = []
            while data[i] != 0:
                count = data[i]
                name = data[i + 1:i + count + 1]
                self.domainList.append((count, name))
                i += (count + 1)
            self.domainStr = b'.'.join([x[1] for x in self.domainList])

            self.domain = data[12:i + 1]
            self.QTYPE = data[i + 1:i + 3]
            self.QCLASS = data[i + 3:i + 5]

            if self.QR == 0x80:  # 响应
                pass

    def genResponse(self, hosts):

        # Header
        newData = bytes()
        newData += self.ID  # ID
        newData += b'\x81\x80'  # Flag
        newData += b'\x00\x01'  # QDCOUNT 问题数量
        newData += b'\x00\x02'  # ANCOUNT 回答数量
        newData += b'\x00\x00'  # NSCOUNT 权威回答数量
        newData += b'\x00\x00'  # ARCOUNT 附加回答数量

        # Question
        newData += self.data[12:-4]  # 和源包中的Question字段相同
        newData += b'\x00\x01\x00\x01'  # Type : CName  Class : IN
        self.data = newData

        # Answer
        self.data += b'\xc0\x0c'  # Name
        self.data += b'\x00\x05'  # Type : CName
        self.data += b'\x00\x01'  # Class : IN
        self.data += b'\x00\x00\x1c\x20'  # TTL:7200
        self.data += b'\x00\x02'  # Data Length
        self.data += b'\xc0\x0c'  # CNAME

        self.data += b'\xc0\x0c'  # Name
        self.data += b'\x00\x01'  # Type: A
        self.data += b'\x00\x01'  # Class:IN
        self.data += b'\x00\x00\x1c\x20'  # TTL:7200
        self.data += b'\x00\x04'  # Data Length

        if self.domainStr.decode('ascii') not in hosts.keys():
            return False
        addr = hosts[self.domainStr.decode('ascii')].split('.')  # addr is a list containing 4 numbers

        addr = list(map(int, addr))  # convert string to int
        # print(addr)
        self.data += struct.pack('BBBB', *addr)
        return self.data


index = 1  # 参数位置
mode = 0  # 调试级别
if index < len(sys.argv):
    if sys.argv[1] == '-d':
        mode = 1  # 仅输出时间坐标，序号，查询的域名
        index += 1
    elif sys.argv[1] == '-dd':
        mode = 2
        index += 1

nameserver = []  # DNS
if index < len(sys.argv):
    if sys.argv[index].count('.') == 3 and sys.argv[index].startswith(
            ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0')):
        nameserver.append(sys.argv[index])
        index += 1

filename = 'dnsrelay.txt'  # hosts文件
if index < len(sys.argv):
    filename = sys.argv[index]

hosts = {}  # read dnsrelay
with open(filename) as file:
    for line in file:
        if len(line) != 1:
            hosts[line.split()[1]] = line.split()[0]

# get local dns
if not nameserver:
    with open('/etc/resolv.conf') as res:
        for line in res:
            s = line.split()
            if s[0] == 'nameserver':
                nameserver.append(s[1])

LocalAddr = ('0.0.0.0', 53)  # 监听的IP和端口
ServerAddr = (nameserver[0], 53)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # SOCK_DGRAM是UDP传输协议
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(LocalAddr)

seq = 0
while True:
    debugInfo1 = {}  # 调试信息
    seq += 1
    debugInfo1['seq'] = seq

    data, SourceAddr = s.recvfrom(2048)
    debugInfo1['time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    P = package(data)
    debugInfo1['domain name'] = P.domainStr.decode('ascii')
    debugInfo2 = {}
    debugInfo2['ID'] = hex(struct.unpack('!H', P.ID)[0])
    debugInfo2['QR'] = P.QR
    debugInfo2['Opcode'] = P.Opcode
    debugInfo2['AA'] = P.AA
    debugInfo2['TC'] = P.TC
    debugInfo2['RD'] = P.RD
    debugInfo2['RA'] = P.RA
    debugInfo2['RCODE'] = P.RCODE
    debugInfo2['QDCOUNT'] = struct.unpack('!H', P.QDCOUNT)[0]  # !H 代表逆序网络字节序解包
    debugInfo2['ANCOUNT'] = struct.unpack('!H', P.ANCOUNT)[0]
    debugInfo2['NSCOUNT'] = struct.unpack('!H', P.NSCOUNT)[0]
    debugInfo2['ARCOUNT'] = struct.unpack('!H', P.ARCOUNT)[0]
    debugInfo2.update(debugInfo1)

    result = P.genResponse(hosts)
    if result:
        debugInfo1['result'] = 'Found it!'
        s.sendto(result, SourceAddr)
    else:  # dnsrelay.txt 中找不到相应的域名,中继数据包
        debugInfo1['result'] = 'Not found!'
        s.sendto(data, ServerAddr)
        data, addr = s.recvfrom(2048)
        s.sendto(data, SourceAddr)

    # 打印调试信息
    if mode == 1:
        pprint(debugInfo1)
    elif mode == 2:
        pprint(debugInfo2)
