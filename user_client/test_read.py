#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_read.py —— 绕过 Fabric/SGX 的读取验证脚本
================================================
目的：在源码运行中证明「为什么把哈希 hm 发送给 BFT 副本，副本就能返回密文」。

原理（对应源码位置）：
  1. 写入：user_client/write_send.py 中生成 hm = SHA256(m)，用 _pack 打包
     (tyke=3, fields, hm, cm) 发送给 BFT 节点消息端口（30000-30600）。
  2. 存储：共识完成后 BFT 节点的 _unpack() 调用 db_put((i, hm, cm))；
     dumbobft/core/dumbo.py 的 db_client() 线程执行 _write(i, hm, cm)，
     即 LevelDB 中以 hm 为 key、cm 为 value 存储。
  3. 读取：本脚本用 _pack(4, b'', hm, b'') 向 BFT 节点发送读取请求
     —— tyke=4 表示 ABE 读取请求（与 inquire_chain.py 的 hm_encrypt 相同）。
  4. 副本处理：dumbo.py db_client() 中 `elif m == 4:` 分支：
         cm = _read(i, key)     # key 就是 hm
     _read() 内部（dumbobft/core/_leveldb.py）：
         db = leveldb.LevelDB(path); m = db.Get(key)   # 哈希即数据库的 Key！
     副本随后把 (tyke=4, hm, cm) 打包发回端口 60000。
  5. 验证：本脚本监听 60000 端口收到 cm 后：
         a. 对比返回的 cm 与数据库中该 hm 对应的 value —— 证明副本返回的
            就是「以 hm 为 key 查到的密文」；
         b. ABE 解密 cm 得到明文 m —— 证明数据可还原；
         c. 校验 SHA256(m) == hm —— 证明「数据库的 key 就是消息的哈希」。

用法（在 Ubuntu 虚拟机中执行）：
  前提：
    - BFT 节点已启动：./run_local_network_test.sh 4 1 10 1000
    - 已用 write_send.py 成功写入过数据（LevelDB 中已有 (hm, cm)）
    - 不要启动 temp_db/main_db.py（60000 端口由本脚本监听）
    - ABE 密钥存在：user_client/attribute_key/{pk.keys, msk.keys}

  运行：
    cd /home/shoe/code/AsynchronousStorage/user_client
    python3 test_read.py
"""

import socket
import struct
import hashlib
import threading
import time
import os
import sys
from io import BytesIO

from charm.toolbox.pairinggroup import PairingGroup
from ABE.ac17 import AC17CPABE

# user_client 目录下的本地模块（注意：该目录的代码与项目根目录版本不同，
# 因此这里只 import 确定存在且签名稳定的函数）
from struct_package.pack_struct import _pack          # 客户端 -> BFT 的打包格式
from struct_package.unpack_struct import attribute_unpack  # 解包 ABE 密文
from crypto.ABE1.att_decrypt import out_key, element_to_bytes, aes_decrypt

# ---------------- 配置 ----------------
BFT_MSG_HOST = '127.0.0.1'
BFT_MSG_PORT = 30000          # 节点 0 的消息端口（hosts_message.config）
DB_RECV_PORT = 60000          # dumbo.py 中 Client_send_db 发送返回数据的端口
RECV_TIMEOUT = 90             # 等待共识完成 + 副本返回的超时（秒）
ATTR_LIST = ['ONE', 'TWO', 'THREE']   # 请求者属性，须满足写入时的策略
                                     # '((ONE and THREE) and (TWO OR FOUR))'
DB_ROOT_CANDIDATES = [
    '../db3',                  # 从 user_client/ 目录运行时
    './db3',                   # 从项目根目录运行时
    '/home/shoe/code/AsynchronousStorage/db3',
]


def _hash(x):
    """与 write_send.py 一致的 SHA-256 哈希。"""
    if isinstance(x, str):
        x = x.encode()
    return hashlib.sha256(x).digest()


def get_len(msg):
    buf = BytesIO()
    buf.write(struct.pack("<i", len(msg)))
    buf.write(msg)
    buf.seek(0)
    return buf.read()


def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def abe_decrypt(ctxt_msg, attr_list):
    """
    解密 attribute_unpack 解出的 [ctxt, encryption]。
    直接使用 charm 的 AC17CPABE（与 user_client/crypto/ABE1/att_decrypt.py
    的 decrypt 内部逻辑一致），避免依赖该文件里签名不一致的 decrypt 函数。
    """
    (pk, msk) = out_key()
    ctxt = ctxt_msg[0]
    encryption = ctxt_msg[1]
    pairing_group = PairingGroup('SS512')
    cpabe = AC17CPABE(pairing_group, 2)
    key = cpabe.keygen(pk, msk, attr_list)
    rec_msg = cpabe.decrypt(pk, ctxt, key)
    aesKey_bytes = element_to_bytes(rec_msg)
    aesKey_bytes32 = aesKey_bytes[0:32]
    return aes_decrypt(aesKey_bytes32, encryption)


def find_db_root():
    """定位 LevelDB 根目录（包含 db3{0..3} 的目录）。"""
    for cand in DB_ROOT_CANDIDATES:
        p = os.path.abspath(cand)
        if os.path.isdir(p):
            return p
    return None


def scan_db(db_root):
    """
    读取所有副本的 LevelDB，返回 {hm: [cm, cm, ...]}。
    这正是写入流程的结果：key=hm, value=cm。
    """
    import leveldb
    data = {}
    for i in range(4):
        path = os.path.join(db_root, 'db3%d' % i)
        if not os.path.isdir(path):
            continue
        try:
            db = leveldb.LevelDB(path)
        except Exception as e:
            print("  无法打开 %s : %s" % (path, e))
            continue
        cnt = 0
        for key, value in db.RangeIter():
            # 该环境的 leveldb 包返回 bytearray（不可哈希），统一转成 bytes
            key = bytes(key)
            value = bytes(value)
            data.setdefault(key, []).append(value)
            cnt += 1
        print("  db3%d  : %d 条记录" % (i, cnt))
    return data


def send_read_request(hm):
    """
    向 BFT 节点发送 ABE 读取请求。
    注意：必须用 _pack(tyke=4, fields=b'', key=hm, m=b'') 的 4 段格式
    （与 inquire_chain.py 的 hm_encrypt 一致），因为 BFT 节点的 _unpack
    按 [tyke | fields | key | m] 解析；db_pake 是副本回传数据用的 3 段格式。
    """
    tx = _pack(4, b'', hm, b'')
    sk = socket.socket()
    sk.connect((BFT_MSG_HOST, BFT_MSG_PORT))
    sk.sendall(get_len(tx))
    sk.close()


class RecvServer(threading.Thread):
    """监听 60000 端口，收集 BFT 副本返回的 (tyke=4, hm, cm) 包。"""

    def __init__(self, results, timeout=RECV_TIMEOUT):
        super().__init__(daemon=True)
        self.results = results
        self.timeout = timeout
        self.ready = threading.Event()

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(('127.0.0.1', DB_RECV_PORT))
        except OSError as e:
            print("\n[错误] 无法监听 %d 端口：%s" % (DB_RECV_PORT, e))
            print("       temp_db/main_db.py 可能正在运行，请先关闭它再运行本脚本。")
            self.ready.set()
            return
        srv.listen(8)
        srv.settimeout(self.timeout)
        self.ready.set()
        print("[接收] 监听 127.0.0.1:%d 等待副本返回...（超时 %ds）"
              % (DB_RECV_PORT, self.timeout))
        try:
            while True:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    print("[接收] 超时，停止监听")
                    break
                with conn:
                    head = recv_exact(conn, 4)
                    if len(head) < 4:
                        continue
                    (size,) = struct.unpack("<i", head)
                    body = recv_exact(conn, size)
                    if len(body) == size:
                        self.results.append(body)
                        print("[接收] 收到副本返回包（%d 字节，来自 %s）"
                              % (size, addr[0]))
        finally:
            srv.close()


def parse_db_response(body):
    """
    解析副本回传包（db_pake 3 段格式，见 dumbo.py db_client）：
    <i tyke><i len(hm)><hm><i len(cm)><cm>
    """
    buf = BytesIO(body)
    (tyke,) = struct.unpack("<i", buf.read(4))
    (hm_len,) = struct.unpack("<i", buf.read(4))
    hm = buf.read(hm_len)
    (cm_len,) = struct.unpack("<i", buf.read(4))
    cm = buf.read(cm_len)
    return tyke, hm, cm


def main():
    print("=" * 70)
    print("FACOS 读取验证：为什么把哈希 hm 发给副本，副本就能返回密文？")
    print("=" * 70)

    # ---- 1. 展示 LevelDB 内容：key=hm, value=cm ----
    db_root = find_db_root()
    if db_root is None:
        print("\n[错误] 找不到 db3 目录（尝试过 %s）" % DB_ROOT_CANDIDATES)
        print("       请确认已运行 write_send.py 写入数据。")
        sys.exit(1)
    print("\n[1] 扫描 LevelDB（%s）：写入流程留下的 (hm -> cm) 键值对" % db_root)
    db_data = scan_db(db_root)
    if not db_data:
        print("\n[错误] 数据库为空！请先运行 write_send.py 写入数据。")
        sys.exit(1)
    for hm, cms in list(db_data.items())[:5]:
        print("    key(hm) = %s...   value(cm) 大小 = %d 字节（%d 个副本）"
              % (hm.hex()[:16], len(cms[0]), len(cms)))

    # ---- 2. 发送读取请求 ----
    print("\n[2] 发送读取请求 _pack(tyke=4, fields=b'', key=hm, m=b'') 到 BFT 节点 %s:%d"
          % (BFT_MSG_HOST, BFT_MSG_PORT))
    print("    tyke=4 表示 ABE 读取请求；hm 作为 key 参与后续查询")
    for hm in db_data:
        print("    -> 发送 hm = %s..." % hm.hex()[:16])
        send_read_request(hm)

    # ---- 3. 接收副本返回 ----
    results = []
    recv = RecvServer(results)
    recv.start()
    recv.ready.wait(timeout=5)
    print("\n[3] 副本处理中（Dumbo 共识 -> db_client -> _read(hm) -> 回传 60000）...")
    while recv.is_alive() and not results:
        time.sleep(1)
    recv.join(timeout=2)

    if not results:
        print("\n[错误] 未收到任何副本返回。请检查：")
        print("       - BFT 节点是否在运行（./run_local_network_test.sh 4 1 10 1000）")
        print("       - 发送请求后共识是否完成（节点终端应打印 'data consensus is complete'）")
        print("       - 终端1 是否出现 'Client_send_db' 相关报错")
        sys.exit(1)

    # ---- 4. 逐条验证 ----
    print("\n[4] 验证副本返回结果")
    seen = set()
    ok_cnt = 0
    for body in results:
        tyke, r_hm, r_cm = parse_db_response(body)
        if r_hm in seen:          # 多个副本返回相同内容，只验证一次
            continue
        seen.add(r_hm)

        print("\n" + "-" * 70)
        print("返回包: tyke=%d  hm=%s..." % (tyke, r_hm.hex()[:16]))

        if r_hm not in db_data:
            print("  [!] 返回的 hm 不在数据库中，跳过")
            continue
        db_cm = db_data[r_hm][0]

        # 4a. 返回的 cm 是否就是数据库中该 key 对应的 value
        if r_cm == db_cm:
            print("  ① 返回的 cm 与数据库中 hm 对应的 value 完全一致（%d 字节）"
                  % len(r_cm))
            print("     -> 证明副本执行的就是 db.Get(hm)，哈希就是数据库的 Key")
        else:
            print("  ① [!] 返回的 cm 与数据库 value 不一致（%d vs %d 字节）"
                  % (len(r_cm), len(db_cm)))

        # 4b. ABE 解密
        try:
            m = attribute_unpack(r_cm)
            plain = abe_decrypt(m, ATTR_LIST)
        except Exception as e:
            print("  ② [!] 解密失败：%s" % e)
            print("     请确认写入时用的是 ABE 模式，且 attribute_key 密钥与写入时一致")
            continue

        # 4c. SHA256(明文) == hm ?
        h2 = _hash(plain)
        match = (h2 == r_hm)
        plain_str = plain.decode('utf-8', errors='replace')
        print("  ② ABE 解密成功，明文 = %s"
              % (plain_str[:60] + ("..." if len(plain_str) > 60 else "")))
        print("  ③ SHA256(明文) = %s..." % h2.hex()[:16])
        print("     hm(数据库key) = %s..." % r_hm.hex()[:16])
        if match:
            print("     => 一致！数据库的 Key 就是消息哈希 hm，闭环验证通过 ✓")
            ok_cnt += 1
        else:
            print("     => [!] 不一致")

    print("\n" + "=" * 70)
    print("结论：%d/%d 条数据完成闭环验证" % (ok_cnt, len(seen)))
    print("  发送 hm  ->  副本 db.Get(hm)  ->  返回密文  ->  解密还原明文")
    print("  哈希 hm 就是 BFT 副本 LevelDB 的分布式数据库 Key，")
    print("  因此把哈希发给副本，副本就能直接命中并返回对应密文。")
    print("=" * 70)


if __name__ == '__main__':
    main()
