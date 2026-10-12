//
//  AceWS.m
//  极简 WebSocket 服务端（仅本机回环，够用即可）
//
#import "AceWS.h"

#import <sys/socket.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <errno.h>
#import <CommonCrypto/CommonDigest.h>

#define ACE_WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

@implementation AceWS {
    int                      _listenFd;
    BOOL                     _running;
    dispatch_queue_t         _acceptQueue;
    dispatch_queue_t         _clientQueue;
    NSMutableDictionary<NSNumber *, NSString *> *_clients;  // fd -> role
}

- (void)log:(NSString *)s {
    NSLog(@"[ACE-WS] %@", s);
    void (^cb)(NSString *) = self.onLog;
    if (cb) cb(s);
}

#pragma mark - 生命周期

- (instancetype)init {
    if ((self = [super init])) {
        _listenFd = -1;
        _clients = [NSMutableDictionary dictionary];
        _acceptQueue = dispatch_queue_create("com.ace.ws.accept", DISPATCH_QUEUE_SERIAL);
        _clientQueue = dispatch_queue_create("com.ace.ws.client", DISPATCH_QUEUE_CONCURRENT);
    }
    return self;
}

- (BOOL)start {
    if (_listenFd >= 0) return YES;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { [self log:@"socket() 失败"]; return NO; }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 只监听本机回环
    addr.sin_port = 0;                                // 端口交给系统分配

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        [self log:[NSString stringWithFormat:@"bind 失败 errno=%d", errno]];
        close(fd);
        return NO;
    }
    if (listen(fd, 16) < 0) {
        [self log:[NSString stringWithFormat:@"listen 失败 errno=%d", errno]];
        close(fd);
        return NO;
    }

    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) < 0) {
        close(fd);
        return NO;
    }
    _port = ntohs(bound.sin_port);
    _listenFd = fd;
    _running = YES;

    [self log:[NSString stringWithFormat:@"监听 ws://127.0.0.1:%u", _port]];

    dispatch_async(_acceptQueue, ^{ [self acceptLoop]; });
    return YES;
}

- (void)stop {
    _running = NO;
    if (_listenFd >= 0) {
        close(_listenFd);
        _listenFd = -1;
    }
    @synchronized (_clients) {
        for (NSNumber *fdNum in _clients) {
            close(fdNum.intValue);
        }
        [_clients removeAllObjects];
    }
    [self log:@"已停止"];
}

- (NSUInteger)clientCount {
    @synchronized (_clients) { return _clients.count; }
}

#pragma mark - accept

- (void)acceptLoop {
    while (_running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(_listenFd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (!_running) break;
            usleep(50000);
            continue;
        }
        int yes = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        dispatch_async(_clientQueue, ^{ [self handleClient:cfd]; });
    }
}

#pragma mark - 握手

- (BOOL)sendAll:(int)fd bytes:(const void *)buf len:(size_t)len {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return NO;
        sent += (size_t)n;
    }
    return YES;
}

- (NSString *)headerValue:(NSString *)name in:(NSString *)headers {
    for (NSString *line in [headers componentsSeparatedByString:@"\r\n"]) {
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound) continue;
        NSString *k = [[line substringToIndex:colon.location]
                       stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([k caseInsensitiveCompare:name] != NSOrderedSame) continue;
        return [[line substringFromIndex:colon.location + 1]
                stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    }
    return nil;
}

- (NSString *)acceptForKey:(NSString *)key {
    NSString *concat = [key stringByAppendingString:[NSString stringWithUTF8String:ACE_WS_MAGIC]];
    NSData *in = [concat dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(in.bytes, (CC_LONG)in.length, digest);
    NSData *d = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    return [d base64EncodedStringWithOptions:0];
}

#pragma mark - 客户端主循环

- (void)handleClient:(int)fd {
    // ---- 1. 读 HTTP 握手请求 ----
    NSMutableData *reqBuf = [NSMutableData data];
    uint8_t tmp[1024];
    NSRange endRange = NSMakeRange(NSNotFound, 0);

    while (reqBuf.length < 16384) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) { close(fd); return; }
        [reqBuf appendBytes:tmp length:(NSUInteger)n];
        endRange = [reqBuf rangeOfData:[@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]
                               options:0 range:NSMakeRange(0, reqBuf.length)];
        if (endRange.location != NSNotFound) break;
    }
    if (endRange.location == NSNotFound) {
        [self log:@"握手请求不完整，断开"];
        close(fd);
        return;
    }

    NSString *headers = [[NSString alloc] initWithData:reqBuf encoding:NSUTF8StringEncoding];
    NSString *key = [self headerValue:@"Sec-WebSocket-Key" in:headers];
    if (!key) {
        [self log:@"缺少 Sec-WebSocket-Key"];
        close(fd);
        return;
    }

    NSString *accept = [self acceptForKey:key];
    NSString *resp = [NSString stringWithFormat:
        @"HTTP/1.1 101 Switching Protocols\r\n"
        @"Upgrade: websocket\r\n"
        @"Connection: Upgrade\r\n"
        @"Sec-WebSocket-Accept: %@\r\n\r\n", accept];

    if (![self sendAll:fd bytes:resp.UTF8String len:strlen(resp.UTF8String)]) {
        close(fd);
        return;
    }

    // ---- 2. 注册客户端（角色等 hello 消息再填） ----
    @synchronized (_clients) { _clients[@(fd)] = @"unknown"; }
    [self log:[NSString stringWithFormat:@"客户端接入 fd=%d 总数=%lu", fd,
               (unsigned long)self.clientCount]];

    // ---- 3. 帧循环 ----
    NSMutableData *acc = [NSMutableData data];
    // 握手时可能已经多读了数据（帧会跟在 \r\n\r\n 后面）
    NSUInteger consumed = endRange.location + 4;
    if (reqBuf.length > consumed) {
        [acc appendData:[reqBuf subdataWithRange:NSMakeRange(consumed, reqBuf.length - consumed)]];
    }

    while (_running) {
        // 解析完整帧
        while (YES) {
            NSData *payload = nil;
            NSUInteger used = 0;
            uint8_t opcode = 0;
            if (![self parseFrame:acc payload:&payload opcode:&opcode used:&used]) break;
            if (used == 0) break;

            [acc replaceBytesInRange:NSMakeRange(0, used) withBytes:NULL length:0];

            if (opcode == 0x8) {   // close
                [self unregister:fd];
                close(fd);
                return;
            }
            if (opcode == 0x9) {   // ping -> pong
                [self sendFrame:fd opcode:0xA payload:[NSData data]];
                continue;
            }
            if (opcode != 0x1 && opcode != 0x2) continue;  // 只处理文本/二进制

            id obj = nil;
            if (payload.length) {
                obj = [NSJSONSerialization JSONObjectWithData:payload options:0 error:nil];
            }
            if (![obj isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *msg = (NSDictionary *)obj;

            // 角色注册
            NSString *role = msg[@"role"];
            if ([msg[@"type"] isEqualToString:@"hello"] && [role isKindOfClass:[NSString class]]) {
                @synchronized (_clients) { _clients[@(fd)] = role; }
                [self log:[NSString stringWithFormat:@"客户端 fd=%d 角色=%@", fd, role]];
            }

            NSString *curRole;
            @synchronized (_clients) { curRole = _clients[@(fd)] ?: @"unknown"; }
            void (^cb)(NSString *, NSDictionary *) = self.onMessage;
            if (cb) cb(curRole, msg);
        }

        // 继续收
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        [acc appendBytes:tmp length:(NSUInteger)n];
    }

    [self unregister:fd];
    close(fd);
}

- (void)unregister:(int)fd {
    @synchronized (_clients) { [_clients removeObjectForKey:@(fd)]; }
    [self log:[NSString stringWithFormat:@"客户端断开 fd=%d 剩余=%lu", fd,
               (unsigned long)self.clientCount]];
}

#pragma mark - 帧解析 / 构造

/// 解析一个帧。成功返回 YES 并填 payload/opcode/used；数据不够返回 NO。
- (BOOL)parseFrame:(NSData *)buf payload:(NSData **)outPayload
            opcode:(uint8_t *)outOpcode used:(NSUInteger *)outUsed {
    if (buf.length < 2) return NO;
    const uint8_t *p = buf.bytes;

    uint8_t opcode = p[0] & 0x0F;
    BOOL masked = (p[1] & 0x80) != 0;
    uint64_t len = p[1] & 0x7F;
    NSUInteger off = 2;

    if (len == 126) {
        if (buf.length < off + 2) return NO;
        len = ((uint64_t)p[off] << 8) | p[off + 1];
        off += 2;
    } else if (len == 127) {
        if (buf.length < off + 8) return NO;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | p[off + i];
        off += 8;
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (buf.length < off + 4) return NO;
        memcpy(mask, p + off, 4);
        off += 4;
    }

    if (buf.length < off + len) return NO;   // 半包，等更多数据

    NSMutableData *pl = [NSMutableData dataWithLength:(NSUInteger)len];
    uint8_t *dst = pl.mutableBytes;
    memcpy(dst, p + off, (NSUInteger)len);
    if (masked) {
        for (uint64_t i = 0; i < len; i++) dst[i] ^= mask[i % 4];
    }

    *outPayload = pl;
    *outOpcode = opcode;
    *outUsed = off + (NSUInteger)len;
    return YES;
}

- (BOOL)sendFrame:(int)fd opcode:(uint8_t)opcode payload:(NSData *)payload {
    NSUInteger len = payload.length;
    NSMutableData *frame = [NSMutableData data];

    uint8_t b0 = 0x80 | (opcode & 0x0F);   // FIN + opcode
    [frame appendBytes:&b0 length:1];

    if (len <= 125) {
        uint8_t b1 = (uint8_t)len;
        [frame appendBytes:&b1 length:1];
    } else if (len <= 65535) {
        uint8_t b1 = 126;
        uint8_t ext[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xFF) };
        [frame appendBytes:&b1 length:1];
        [frame appendBytes:ext length:2];
    } else {
        uint8_t b1 = 127;
        uint8_t ext[8];
        for (int i = 0; i < 8; i++) ext[i] = (uint8_t)(len >> (56 - 8 * i));
        [frame appendBytes:&b1 length:1];
        [frame appendBytes:ext length:8];
    }
    [frame appendData:payload];

    return [self sendAll:fd bytes:frame.bytes len:frame.length];
}

#pragma mark - 广播

- (void)send:(NSDictionary *)obj toRole:(NSString *)role {
    NSData *json = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    if (!json) return;

    NSArray<NSNumber *> *fds;
    @synchronized (_clients) { fds = _clients.allKeys; }

    for (NSNumber *fdNum in fds) {
        if (role) {
            NSString *cur;
            @synchronized (_clients) { cur = _clients[fdNum]; }
            if (![cur isEqualToString:role]) continue;
        }
        [self sendFrame:fdNum.intValue opcode:0x1 payload:json];
    }
}

@end
