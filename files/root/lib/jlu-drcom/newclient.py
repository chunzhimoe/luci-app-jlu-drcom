#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket, struct, time
from hashlib import md5
import sys
import os
import random
import re

# CONFIG
# load config from /etc/config/jlu-drcom
confile = open("/etc/config/jlu-drcom", "r")
conf = confile.read()
confile.close()
confs = conf.split("\n")
for i in confs:
    if i.find("mac") > 0:
        s = i.find("'")
        mac = i[s+1:s+18]
        mac = mac.split(":")
        mac = int("".join(mac), 16)
    if i.find("name") > 0:
        s = i.find("'")
        host_name = i[s+1:-1]
    if i.find("os") > 0:
        s = i.find("'")
        host_os = i[s+1:-1]
    if i.find("ip") > 0:
        s = i.find("'")
        host_ip = i[s+1:-1]
    if i.find("username") > 0:
        s = i.find("'")
        username = i[s+1:-1]
    if i.find("password") > 0:
        s = i.find("'")
        password = i[s+1:-1]
    if i.find("reconnect") > 0:
        s = i.find("'")
        reconnect = i[s+1:-1]

server = '10.100.61.3'
CONTROLCHECKSTATUS = b'\x20'
ADAPTERNUM = b'\x03'
IPDOG = b'\x01'
PRIMARY_DNS = '10.10.10.10'
dhcp_server = '0.0.0.0'
AUTH_VERSION = b'\x68\x00'
KEEP_ALIVE_VERSION = b'\xdc\x02'
# CONFIG_END

nic_name = ''
bind_ip = '0.0.0.0'

class ChallengeException(Exception):
    pass

class LoginException(Exception):
    pass

def bind_nic():
    try:
        import fcntl
        def get_ip_address(ifname):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15].encode())
            )[20:24])
        return get_ip_address(nic_name)
    except ImportError:
        print('Indicate nic feature need to be run under Unix based system.')
        return '0.0.0.0'
    except IOError:
        print(nic_name + ' is unacceptable!')
        return '0.0.0.0'
    finally:
        return '0.0.0.0'

if nic_name != '':
    bind_ip = bind_nic()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((bind_ip, 61440))
s.settimeout(3)

SALT = b''
IS_TEST = True
CONF = "/etc/drcom.conf"
UNLIMITED_RETRY = True
DEBUG = True
LOG_PATH = '/var/log/drcom_client.log'
if IS_TEST:
    DEBUG = True
    LOG_PATH = 'drcom_client.log'


def log(*args):
    msg = ' '.join(str(a) for a in args)
    print(msg)
    if DEBUG:
        with open(LOG_PATH, 'a') as f:
            f.write(msg + '\n')


def challenge(svr, ran):
    while True:
        t = struct.pack("<H", int(ran) % 0xFFFF)
        s.sendto(b"\x01\x02" + t + b"\x09" + b"\x00" * 15, (svr, 61440))
        data, address = s.recvfrom(1024)
        log('[challenge] recv', data.hex())
        if address == (svr, 61440):
            break
        else:
            continue
    log('[DEBUG] challenge:\n' + data.hex())
    if data[0] != 0x02:
        raise ChallengeException
    log('[challenge] challenge packet sent.')
    return data[4:8]


def md5sum(b):
    m = md5()
    m.update(b)
    return m.digest()


def dump(n):
    h = '%x' % n
    if len(h) & 1:
        h = '0' + h
    return bytes.fromhex(h)


def ror(md5b, pwd):
    # Both arguments should be bytes
    if isinstance(pwd, str):
        pwd = pwd.encode('latin-1')
    ret = b''
    for i in range(len(pwd)):
        x = md5b[i] ^ pwd[i]
        ret += bytes([((x << 3) & 0xFF) + (x >> 5)])
    return ret


def keep_alive_package_builder(number, ran_bytes, tail, pkt_type=1, first=False):
    data = bytes([0x07, number, 0x28, 0x00, 0x0b, pkt_type])
    if first:
        data += b'\x0f\x27'
    else:
        data += KEEP_ALIVE_VERSION
    data += b'\x2f\x12' + b'\x00' * 6
    data += tail
    data += b'\x00' * 4
    if pkt_type == 3:
        foo = bytes([int(i) for i in host_ip.split('.')])
        crc = b'\x00' * 4
        data += crc + foo + b'\x00' * 8
    else:
        data += b'\x00' * 16
    return data


def keep_alive2(*args):
    tail = b''
    svr = server
    ran = random.randint(0, 0xFFFF)
    ran += random.randint(1, 10)
    svr_num = 0
    packet = keep_alive_package_builder(svr_num, dump(ran), b'\x00' * 4, 1, True)

    while True:
        log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'send1', packet.hex())
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        log('[keep-alive2] recv1', data.hex())
        if data[:4] == b'\x07\x00\x28\x00' or (data[0] == 0x07 and data[1] == svr_num and data[2:4] == b'\x28\x00'):
            break
        elif data[0] == 0x07 and data[2] == 0x10:
            log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv file, resending..')
            svr_num += 1
            packet = keep_alive_package_builder(svr_num, dump(ran), b'\x00' * 4, 1, False)
        else:
            log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv1/unexpected', data.hex())

    ran += random.randint(1, 10)
    packet = keep_alive_package_builder(svr_num, dump(ran), b'\x00' * 4, 1, False)
    log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'send2', packet.hex())
    s.sendto(packet, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == 0x07:
            svr_num += 1
            break
        else:
            log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv2/unexpected', data.hex())
    log('[keep-alive2] recv2', data.hex())
    tail = data[16:20]

    ran += random.randint(1, 10)
    packet = keep_alive_package_builder(svr_num, dump(ran), tail, 3, False)
    log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'send3', packet.hex())
    s.sendto(packet, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        if data[0] == 0x07:
            svr_num += 1
            break
        else:
            log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv3/unexpected', data.hex())
    log('[keep-alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv3', data.hex())
    tail = data[16:20]
    log("[keep-alive2]", time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), "keep-alive2 loop was in daemon.")

    i = svr_num
    err_count = 0
    while True:
        try:
            ran += random.randint(1, 10)
            packet = keep_alive_package_builder(i, dump(ran), tail, 1, False)
            log('[keep_alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'send', str(i), packet.hex())
            s.sendto(packet, (svr, 61440))
            data, address = s.recvfrom(1024)
            log('[keep_alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv', data.hex())
            tail = data[16:20]

            ran += random.randint(1, 10)
            packet = keep_alive_package_builder(i + 1, dump(ran), tail, 3, False)
            s.sendto(packet, (svr, 61440))
            log('[keep_alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'send', str(i + 1), packet.hex())
            data, address = s.recvfrom(1024)
            log('[keep_alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), 'recv', data.hex())
            tail = data[16:20]
            i = (i + 2) % 0xFF
            time.sleep(20)
            keep_alive1(*args)
            err_count = 0
        except Exception:
            err_count += 1
            if err_count >= 5:
                log('[keep_alive2]', time.strftime('[%Y-%m-%d %H:%M:%S]', time.localtime()), "FATAL ERROR: CONNECTION ERROR.")
                exit()


def checksum(data):
    ret = 1234
    for i in re.findall(b'....', data):
        ret ^= int(i[::-1].hex(), 16)
    ret = (1968 * ret) & 0xffffffff
    return struct.pack('<I', ret)


def mkpkt(salt, usr, pwd, mac):
    if isinstance(usr, str):
        usr = usr.encode('latin-1')
    if isinstance(pwd, str):
        pwd = pwd.encode('latin-1')

    data = b'\x03\x01\x00' + bytes([len(usr) + 20])
    data += md5sum(b'\x03\x01' + salt + pwd)
    data += usr.ljust(36, b'\x00')
    data += CONTROLCHECKSTATUS
    data += ADAPTERNUM
    data += dump(int(data[4:10].hex(), 16) ^ mac).rjust(6, b'\x00')
    data += md5sum(b'\x01' + pwd + salt + b'\x00' * 4)
    data += b'\x01'
    data += bytes([int(i) for i in host_ip.split('.')])
    data += b'\x00' * 4
    data += b'\x00' * 4
    data += b'\x00' * 4
    data += md5sum(data + b'\x14\x00\x07\x0b')[:8]
    data += IPDOG
    data += b'\x00' * 4
    data += host_name.encode('latin-1').ljust(32, b'\x00')
    data += bytes([int(i) for i in PRIMARY_DNS.split('.')])
    data += bytes([int(i) for i in dhcp_server.split('.')])
    data += b'\x00\x00\x00\x00'
    data += b'\x00' * 8
    data += b'\x94\x00\x00\x00'
    data += b'\x06\x00\x00\x00'
    data += b'\x02\x00\x00\x00'
    data += b'\xf0\x23\x00\x00'
    data += b'\x02\x00\x00\x00'
    data += b'\x44\x72\x43\x4f\x4d\x00\xcf\x07\x68'
    data += b'\x00' * 55
    data += b'\x33\x64\x63\x37\x39\x66\x35\x32\x31\x32\x65\x38\x31\x37\x30\x61\x63\x66\x61\x39\x65\x63\x39\x35\x66\x31\x64\x37\x34\x39\x31\x36\x35\x34\x32\x62\x65\x37\x62\x31'
    data += b'\x00' * 24
    data += AUTH_VERSION
    data += b'\x00' + bytes([len(pwd)])
    data += ror(md5sum(b'\x03\x01' + salt + pwd), pwd)
    data += b'\x02\x0c'
    data += checksum(data + b'\x01\x26\x07\x11\x00\x00' + dump(mac))
    data += b'\x00\x00'
    data += dump(mac)
    pad_len = len(pwd) // 4
    if pad_len != 4:
        data += b'\x00' * pad_len
    data += b'\x60\xa2'
    data += b'\x00' * 28
    log('[mkpkt]', data.hex())
    return data


def login(usr, pwd, svr):
    global SALT
    i = 0
    while True:
        salt = challenge(svr, time.time() + random.randint(0xF, 0xFF))
        SALT = salt
        packet = mkpkt(salt, usr, pwd, mac)
        log('[login] send', packet.hex())
        s.sendto(packet, (svr, 61440))
        data, address = s.recvfrom(1024)
        log('[login] recv', data.hex())
        log('[login] packet sent.')
        if address == (svr, 61440):
            if data[0] == 0x04:
                log('[login] loged in')
                break
            else:
                log('[login] login failed.')
                if IS_TEST:
                    time.sleep(3)
                else:
                    time.sleep(30)
                continue
        else:
            if i >= 5 and not UNLIMITED_RETRY:
                log('[login] exception occured.')
                sys.exit(1)
            else:
                i += 1
                continue
    log('[login] login sent')
    return data[23:39]


def keep_alive1(salt, tail, pwd, svr):
    if isinstance(pwd, str):
        pwd = pwd.encode('latin-1')
    foo = struct.pack('!H', int(time.time()) % 0xFFFF)
    data = b'\xff' + md5sum(b'\x03\x01' + salt + pwd) + b'\x00\x00\x00'
    data += tail
    data += foo + b'\x00\x00\x00\x00'
    log('[keep_alive1] send', data.hex())
    s.sendto(data, (svr, 61440))
    while True:
        data, address = s.recvfrom(1024)
        print(data.hex())
        if data[0] == 0x07:
            break
        else:
            log('[keep-alive1] recv/not expected', data.hex())
    log('[keep-alive1] recv', data.hex())


def empty_socket_buffer():
    log('starting to empty socket buffer')
    try:
        while True:
            data, address = s.recvfrom(1024)
            log('recived sth unexpected', data.hex())
            if data == b'':
                break
    except Exception:
        log('exception in empty_socket_buffer')
        pass
    log('emptyed')


def daemon():
    with open('/var/run/jludrcom.pid', 'w') as f:
        f.write(str(os.getpid()))


def main():
    if not IS_TEST:
        daemon()
        exec(open(CONF).read(), globals())
    log("auth svr:" + server + "\nusername:" + username + "\npassword:" + password + "\nmac:" + str(hex(mac)))
    log(bind_ip)
    while True:
        try:
            package_tail = login(username, password, server)
        except LoginException:
            continue
        log('package_tail', package_tail.hex())
        empty_socket_buffer()
        keep_alive1(SALT, package_tail, password, server)
        keep_alive2(SALT, package_tail, password, server)


if __name__ == "__main__":
    main()
