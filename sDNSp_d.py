# coding=utf-8
# display text on a Windows console
# Windows XP with Python27 or Python32+
from ctypes import windll
STD_OUTPUT_HANDLE = -11
stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
def cprint(_args, color):   # 被多线程调用，应该加个锁，暂时先这样了
    windll.kernel32.SetConsoleTextAttribute(stdout_handle, color)
    print(_args)
    windll.kernel32.SetConsoleTextAttribute(stdout_handle, 7)

import sys, time, datetime, random, threading, traceback, struct, json, socketserver, pycurl
from collections import OrderedDict
from io import BytesIO
from IPy import IP
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

Bind_IP = '0.0.0.0'
Bind_PORT = 5053
eip_ECS = 1  # 启用本地外网IP探测，并提交edns_client_subnet
Ext_eip = 1  # 启用扩展IP探测，遍历IP列表(ipl)，返回Google探测到的源IP(可能是本地外网IP或其它出口IP，也可能是代理的IP)。ipl较大时，启动会很慢
'''
不提交edns_client_subnet时，Google会根据探测到的源IP自动判断并返回最优结果（这里“源”是指此DNS代理，注意与DNS客户端的查询“请求源”区分）
如果IP列表(ipl)里有非Google/GGC的IP(如SNI代理等)，请启用本地外网IP探测，提交edns_client_subnet，因为使用代理IP时，Google探测到的“源”是代理的IP

网络接入的几种情况：
① 有公网IP，连到Google或任意IP查询网站，查询结果是相同的，电信、联通的公网IP一般是这种情况。
② 无公网IP，动态出口（例如：运营商级NAT等），私网IP详见：https://zh.wikipedia.org/wiki/%E4%BF%9D%E7%95%99IP%E5%9C%B0%E5%9D%80
③ 有公网IP，跨ISP时走动态出口(≠公网IP)，连到支持你所用ISP的BGP线路时，探测到的IP是唯一的(ISP为你分配的公网IP)
   但是连到其它ISP或者国外线路时，使用的是动态出口（可能是移动、联通或者电信）。使用长城宽带等二级ISP时这种情况比较常见

两种服务部署方式：
一、在本地做DNS代理：
①和② 无需提交edns_client_subnet
③ 建议启用本地外网IP探测并提交edns_client_subnet，因为Google探测到的的“源”并不是你的实际IP。否则访问一些支持CDN的网站可能会绕远

二、远程DNS代理：（将服务部署在有公网IP的主机或VPS上）
如果DNS查询的请求源不是公网IP（来自本机或内网），查询请求的处理如同本地DNS代理行为，否则：
  将请求源的IP作为edns_client_subnet参数提交，即根据DNS查询“请求源”的IP地址返回DNS查询结果，此时DNS客户端的情况：
    ① DNS代理将探测到固定IP
    ② DNS代理探测到动态IP
    ③ DNS代理探测到的IP不确定，需要向DNS代理发送域名查询:"myip"来确定出口情况。
    无论哪种情况，DNS代理总是将探测到的客户端IP作为edns_client_subnet参数提交
       ①和②一般不会有DNS返回非最优IP的问题
       ③的情况下，DNS代理无法保证返回最优IP，建议在客户端本地部署DNS代理
'''

ipl=['202.86.162.172',
    '219.76.4.3',
    '219.76.4.4',
    '203.210.8.159',
    '203.210.8.163',
    '203.210.8.165',
    '203.210.8.166',
    '203.210.8.170',
    '203.210.8.174',
    '203.210.8.176',
    '203.210.8.177',
    '203.210.8.181',
    '203.210.8.185',
    '203.210.8.187',
]

iil=list(range(len(ipl)))   # [i for i,j in enumerate(ipl)] 生成一个索引列表
dil={}.fromkeys(ipl,0)  # dict([i,0] for i in ipl)  dict(zip(ipl,[0]*ips))  ipl 超时/无效计数
sil={}.fromkeys(ipl,0)  # ipl 成功计数

# get my ip ---------------------------------------------------------------------
def myIP():
    qip = OrderedDict()
    qip['IP6655'] = 'http://ip.6655.com/ip.aspx'    # 北京百度BGP
    qip['Taobao'] = 'http://ip.taobao.com/service/getIpInfo.php?ip=myip'    # 阿里云BGP
    qip['g_cn']='https://redirector.gvt1.com/report_mapping'    # google.cn BGP
    fb = True; wr_buf = b''

    def wdf(buf):
        nonlocal fb, wr_buf
        if fb: wr_buf = buf.decode().split('Debug')[0].split(); fb = False

    c = pycurl.Curl()
    c.setopt(c.NOPROGRESS, 1)
    c.setopt(c.CONNECTTIMEOUT_MS, 800)
    c.setopt(c.TIMEOUT_MS, 2800)
    c.setopt(c.MAXREDIRS, 0)
    c.setopt(c.USERAGENT, 'Curl')   # 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.109 Safari/537.36'

    for u in qip:
        c.setopt(c.URL, qip[u])
        if u == 'Taobao':
            buffer = BytesIO()
            c.setopt(c.WRITEDATA, buffer)
            try: c.perform()
            except pycurl.error as err: cprint("[Error]:[%s] %s" % (u, err), 0xE); qip.pop(u)
            else: qip[u]=json.loads(buffer.getvalue().decode())['data']['ip']
            del buffer
        else:
            c.setopt(c.WRITEFUNCTION, wdf)
            if u == 'g_cn':
                c.setopt(c.RESOLVE, ['redirector.gvt1.com:443:203.208.48.66'])
                c.setopt(c.SSLVERSION, c.SSLVERSION_TLSv1_2)
                c.setopt(c.SSL_VERIFYPEER, 0)
                c.setopt(c.SSL_VERIFYHOST, 0)
                c.setopt(c.SSL_ENABLE_NPN, 1)
                c.setopt(c.SSL_ENABLE_ALPN, 0)
            try: c.perform()
            except pycurl.error as err: cprint("[Error]:[%s] %s" % (u, err), 0xE); qip.pop(u)
            else: qip[u]=wr_buf[0]; fb = True
    c.close(); del c
    # global eip
    if len(set(qip.values())) == 1: eip = list(qip.values())[0] # 判断外网IP是否唯一
    
    if Ext_eip: # 扩展IP探测
        p=[]
        for i,ip in enumerate(ipl):
            buf = BytesIO()
            c = pycurl.Curl()
            #c.setopt(c.VERBOSE, 1)  # 显示详细输出，调试用
            c.setopt(c.NOPROGRESS, 1)
            c.setopt(c.CONNECTTIMEOUT_MS, 600) # 连接阶段超时时间，毫秒为单位
            c.setopt(c.TIMEOUT_MS, 1200)
            c.setopt(c.MAXREDIRS, 0)
            c.setopt(c.USERAGENT, 'Curl')
            c.setopt(c.DEFAULT_PROTOCOL, 'https')   # 默认协议
            c.setopt(c.HTTP_VERSION, 2)  # CURL_HTTP_VERSION_2TLS  CURL_HTTP_VERSION_LAST  不支持HTTP2？？？
            c.setopt(c.SSLVERSION, c.SSLVERSION_TLSv1_2)  # 设置首选 TLS/SSL 版本
            c.setopt(c.SSL_VERIFYPEER, 0)
            c.setopt(c.SSL_VERIFYHOST, 0)
            c.setopt(c.SSL_ENABLE_NPN, 0)   # NPN 协商 服务器发送所支持的HTTP协议列表，由客户端进行选择。将弃用
            c.setopt(c.SSL_ENABLE_ALPN, 0)  # ALPN 协商 客户端发送该列表，由服务端选择。
            c.setopt(c.RESOLVE, ['redirector.gvt1.com:443:'+ip])
            c.setopt(c.URL, 'redirector.gvt1.com/report_mapping')
            c.setopt(c.WRITEFUNCTION, wdf)
            try: c.perform()
            except pycurl.error as err: cprint("[Error]:[%s] %s" % (ip, err), 0xE); # qip[ip]=err
            else: qip[ip]=wr_buf[0],wr_buf[8][1:-1]; fb = True; p.append(ip); print('cip = %s\t%r\n----------<<<<<<<<<<<<<<<<<<<<'%(c.getinfo(c.PRIMARY_IP),qip[ip]))
            time.sleep(.3)
            c.close()
            del c, buf
    for i in qip:
        if i in p:
            if i in IP(qip[i][1]): cprint('To_{:<18}[{:<18}*该IP可能为代理，如果使用此IP，请确认已启用"eip_ECS"'.format(i+':',qip[i][0]+']'),2)
            else: print('To_{:<18}[{}]'.format(i+':',qip[i][0]))
        else: print('To_{:<18}[{}]'.format(i+':',qip[i]))
    if 'eip' in dir(): return eip   # 判断变量是否存在'var' in locals().keys()  locals().has_key('var')
    else: return ''

# Get Google DNS-over-HTTPS response random ---------------------------------------------------------------------
def cget(qn='g.cn', eip=''):
    if eip != '': eip='&edns_client_subnet='+eip
    buf = BytesIO()
    il=iil[:]   # 复制一份iil，因为列表对象不会自动复制
    random.shuffle(il)  # 随机索引 打乱il   # random.randint(0,len(il)-1)
    # print('Qname=%s\nil=%r'%(qn,il))
    for i in il:
        if f[i]:    # 加个标记锁，防止多个线程同时调用一个Curl对象时出错 "cannot invoke setopt() - perform() is currently running"
            f[i] = False    #; ip = ipl[i]
            c[i].setopt(c[i].WRITEDATA, buf)
            c[i].setopt(c[i].URL, 'https://dns.google.com/resolve?name=' + qn + eip)
            for n in range(2):  # 超时后重试
                try: c[i].perform()
                except pycurl.error as err: # 请求超时
                    dil[ipl[i]] += 1    # IP超时计数
                    cprint("[Error-%d]:[%s] %s" % (n+1,ipl[i], err), 14)
                else:
                    cprint('[%s]: 新建连接: %d (Time:%dms Speed:%d)' % (ipl[i], c[i].getinfo(c[i].NUM_CONNECTS),c[i].getinfo(c[i].TOTAL_TIME)*1000,c[i].getinfo(c[i].SPEED_DOWNLOAD)),2)
                    rsp = buf.getvalue()
                    if len(rsp) > 8 and rsp[:9] == b'{"Status"': f[i] = True; sil[ipl[i]] += 1; del buf; return rsp # 检查数据并返回
                    else: dil[ipl[i]] += 1; cprint('[Error]: -----rsp data Error----:\tip==[%s]\n%s\n'%(ipl[i],rsp),14); break
            f[i] = True
            ei = dil[ipl[i]]; si = sil[ipl[i]]  # 统计IP出错次数，动态剔除
            if ei/(ei+si) > 0.618 and ei > 20: cprint('---Connect to [%s] Err:%d|OK:%d\t Remove it!'%(ipl[i],ei,si),12); iil.remove(i); print([ipl[i] for i in iil])
        time.sleep(.3)
        # IP全部超时或都在使用中，请增加IP或者适当调高上一行time.sleep的值
        if i == il[len(il)-1]: cprint('[Error]:Resolve [%s] failed! all ip connect error in ipl;\n'%qn,5)
    del buf, il


def dns_response(data, cip):
    request = DNSRecord.parse(data)
    cprint(request,2)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    qn = str(request.q.qname)
    if qn == 'myip.': reply.add_answer(RR(qn, 1, 1, 0, A(cip))); return reply.pack()    # 返回客户端IP(请求源) ttl=0
    if IP(cip).iptype() != 'PUBLIC': cip = eip  # 非公网请求源
    rsp = cget(qn, cip)
    if rsp is None: reply.add_answer(RR(qn, 1, 1, 0, A('0.1.0.1'))); return reply.pack() # cget 没有返回数据，返回一个 ttl=0 的A记录：0.1.0.1
    else:
        resp = json.loads(rsp.decode())
        if resp['Status'] == 0:
            if 'Answer' in resp:
                for a in resp['Answer']:
                    # reply.add_answer(RR(a['name'], a['type'], 1, a['TTL'], A(a['data'])))   # 完整记录，包含CNAME
                    if a['type'] == 1: reply.add_answer(RR(qn, 1, 1, a['TTL'], A(a['data'])))   # 仅返回'A'记录
                    # 记录格式和默认值: RR(rname=None, rtype=1, rclass=1, ttl=0, rdata=None)
#       elif resp['Status'] == 3: 
#       else: 
        if 'Authority' in resp:
            for a in resp['Authority']: # 权威数据
                reply.add_auth(*RR.fromZone('{} {} {} {}'.format(a['name'],a['TTL'],QTYPE[a['type']],a['data'])))
        cprint('---- Reply:\n%r'%reply,13)
        return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self): raise NotImplementedError

    def send_data(self, data): raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0], self.client_address[1]))
        try:
            data = self.get_data()
            print('%s'%''.join('%02X '%x for x in data), end='\n')  # repr(data).replace('\\x', '')[1:-1]
            if len(data) > 12: self.send_data(dns_response(data, self.client_address[0]))
            else: cprint('The received data is not a DNS request. ignore it!', 14)
        except Exception: traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192)
        sz = int.from_bytes(data[:2],'big')
        # struct.unpack('!H',data[:2])[0]  int(binascii.hexlify(data[:2]),16)  int.from_bytes([255,255,255,255],'big')  codecs.encode(b'\x12\xcd','hex')
        if sz != len(data) - 2: cprint('len=%d\n%s'%(len(data),''.join('%02X '%x for x in data)), 14); raise Exception("Wrong size of TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('!H',len(data))    # len(data).to_bytes(2,'big') 注意 int.from_bytes 和 int.to_bytes 慢于 struct.pack 和 struct.unpack
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':

    if eip_ECS: print('正在获取外网IP，请稍后。。。'); eip = myIP(); cprint('\nMy IP is: [%s]\n'%eip, 10)
    else: eip = ''

    # Curl obj list init  ---------------------------------------------------------------------
    c = []; f = []
    for i,ip in enumerate(ipl):
        f.append(True)
        c.append(pycurl.Curl())
        c[i].setopt(pycurl.NOPROGRESS, 1)
        c[i].setopt(pycurl.CONNECTTIMEOUT_MS, 600)
        c[i].setopt(pycurl.TIMEOUT_MS, 1600)
        c[i].setopt(c[i].MAXREDIRS, 0)
        c[i].setopt(c[i].USERAGENT, 'Curl')
        c[i].setopt(c[i].TCP_KEEPALIVE, 1)
        c[i].setopt(c[i].TCP_KEEPIDLE, 300)
        c[i].setopt(c[i].TCP_KEEPINTVL, 60)
        c[i].setopt(c[i].DEFAULT_PROTOCOL, 'https')
        c[i].setopt(c[i].SSLVERSION, c[i].SSLVERSION_TLSv1_2)
        c[i].setopt(c[i].SSL_VERIFYPEER, 0)
        c[i].setopt(c[i].SSL_VERIFYHOST, 0)
        c[i].setopt(c[i].SSL_ENABLE_NPN, 0) 
        c[i].setopt(c[i].SSL_ENABLE_ALPN, 0)
        c[i].setopt(c[i].RESOLVE, ['dns.google.com:443:'+ip])

    print("Starting Server...")
    servers = [
        socketserver.ThreadingUDPServer((Bind_IP, Bind_PORT), UDPRequestHandler),
        socketserver.ThreadingTCPServer((Bind_IP, Bind_PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("Server loop running in %s: [%s] %s:%s" % (thread.name, s.RequestHandlerClass.__name__[:3], Bind_IP,Bind_PORT))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt: pass
    finally:
        for ci in c:
            try: ci.close()
            except: pass
        del c
        for s in servers:
            s.shutdown()
