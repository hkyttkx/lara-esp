//
//  AceESP.mm
//  王牌战争 ESP — 实现层
//
//  依赖（全部来自 lara 现成代码）：
//    kexploit/darksword  → 内核读写
//    kexploit/utils      → 进程定位
//    kexploit/TaskRop/RemoteCall → 跨进程调用
//
#import "AceESP.h"
#import "AceOffsets.h"
#import "AceWS.h"
#import "AceOverlay.h"

#import "../kexploit/darksword.h"
#import "../kexploit/utils.h"
#import "../kexploit/TaskRop/RemoteCall.h"

#import <dlfcn.h>
#import <string.h>
#import <stdarg.h>

// Darwin 上 RTLD_DEFAULT 的特殊取值
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)-2)
#endif

static inline uint64_t ace_sym(const char *name) {
    return (uint64_t)dlsym(RTLD_DEFAULT, name);
}

@implementation AceESP {
    RemoteCall *_rc;
    uint64_t    _scratch;          // 目标进程内 4KB 暂存区
    dispatch_queue_t _espQueue;    // 串行队列：所有内核/远程调用都在这里

    AceWS      *_ws;
    AceOverlay *_overlay;
    dispatch_source_t _renderTimer;

    uint64_t    _battleKlass;      // Il2CppClass* (Battle)
    uint64_t    _battle;           // Battle.Ins

    // il2cpp 运行时函数（地址属于目标进程）
    uint64_t _fn_domain_get;
    uint64_t _fn_domain_assembly_open;
    uint64_t _fn_assembly_get_image;
    uint64_t _fn_class_from_name;
    uint64_t _fn_class_get_field_from_name;
    uint64_t _fn_field_static_get_value;
    uint64_t _fn_class_get_method_from_name;
    uint64_t _fn_runtime_invoke;

    // 相机投影
    uint64_t _w2sMethod;
    BOOL     _hasProjection;
}

#pragma mark - 单例

+ (instancetype)shared {
    static AceESP *inst;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [AceESP new]; });
    return inst;
}

- (instancetype)init {
    if ((self = [super init])) {
        _targetProcess = @"";
        // 所有内核/远程调用都串行跑在这条队列上。
        // 绝不能放主线程：RemoteCall 初始化 + il2cpp 符号解析累计十几秒，
        // 主线程会被 iOS 看门狗直接杀掉。
        _espQueue = dispatch_queue_create("com.ace.esp.serial", DISPATCH_QUEUE_SERIAL);
        dispatch_set_target_queue(_espQueue,
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));

        // 绘制开关默认值
        _optBox = YES;
        _optLine = YES;
        _optName = YES;
        _optHealth = YES;
        _optDistance = NO;
    }
    return self;
}

#pragma mark - 异步包装

- (void)startAsync:(void (^)(BOOL))completion {
    dispatch_async(_espQueue, ^{
        BOOL ok = [self start];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok);
        });
    });
}

- (void)dumpOnceAsync {
    dispatch_async(_espQueue, ^{
        [self dumpOnce];
    });
}

- (void)listProcessesAsync {
    dispatch_async(_espQueue, ^{
        NSArray<NSString *> *all = [self listProcesses];
        if (all.count == 0) {
            [self log:@"进程列表为空（内核可能没就绪）"];
            return;
        }
        [self log:@"========== 进程列表 (%lu) ==========", (unsigned long)all.count];
        for (NSString *s in all) [self log:@"  %@", s];
        [self log:@"========== 结束 =========="];
    });
}

#pragma mark - 日志

- (void)log:(NSString *)fmt, ... {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[ACE] %@", s);
    void (^cb)(NSString *) = self.logBlock;
    if (cb) cb(s);
}

#pragma mark - 跨进程小工具

- (uint64_t)call:(uint64_t)fn args:(uint64_t *)args count:(NSUInteger)count {
    return [_rc doRemoteCallStableWithTimeout:3000
                                 functionName:(char *)"ace"
                              functionPointer:(void *)fn
                                         args:args
                                     argCount:count];
}

- (uint64_t)remoteDlsym:(const char *)sym {
    if (![_rc remote_write:_scratch string:sym]) return 0;
    uint64_t args[2] = { (uint64_t)RTLD_DEFAULT, _scratch };
    return [self call:ace_sym("dlsym") args:args count:2];
}

- (BOOL)writeStr:(const char *)s at:(uint64_t)addr {
    return [_rc remote_write:addr string:s];
}

#pragma mark - 启动

- (BOOL)start {
    if (!ds_is_ready()) {
        [self log:@"内核未就绪：请先跑 init_offsets() + ds_run()"];
        return NO;
    }

    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    _rc = [[RemoteCall alloc] initWithProcess:_targetProcess useMigFilterBypass:NO];
    if (!_rc) {
        [self log:@"连接进程失败：%@", [RemoteCall lastInitError]];
        [self log:@"注意：这里要填【进程名 / 可执行文件名】，不是 Bundle ID"];
        [self suggestFor:_targetProcess];
        return NO;
    }
    [self log:@"已连接进程 %@ (pid=%d) 耗时 %.1fs",
          _targetProcess, _rc.pid, CFAbsoluteTimeGetCurrent() - t0];

    // 目标进程内申请暂存区
    uint64_t args[1] = { ACE_SCRATCH_SIZE };
    _scratch = [self call:ace_sym("malloc") args:args count:1];
    if (!_scratch) {
        [self log:@"远程 malloc 失败"];
        return NO;
    }
    [self log:@"暂存区 @ 0x%llx", _scratch];

    CFAbsoluteTime t1 = CFAbsoluteTimeGetCurrent();
    if (![self resolveIl2Cpp]) return NO;
    [self log:@"il2cpp 符号解析完成，耗时 %.1fs", CFAbsoluteTimeGetCurrent() - t1];

    CFAbsoluteTime t2 = CFAbsoluteTimeGetCurrent();
    if (![self resolveBattle]) return NO;
    [self log:@"Battle 解析完成，耗时 %.1fs", CFAbsoluteTimeGetCurrent() - t2];

    // 投影方法拿不到不算致命——没有它 ESP 照样能跑雷达
    CFAbsoluteTime t3 = CFAbsoluteTimeGetCurrent();
    _hasProjection = [self resolveProjection];
    [self log:@"投影方法 %@，耗时 %.1fs",
          _hasProjection ? @"已就绪" : @"未就绪（只影响屏幕画框）",
          CFAbsoluteTimeGetCurrent() - t3];

    self.ready = YES;
    self.running = YES;
    [self log:@"初始化完成，总耗时 %.1fs", CFAbsoluteTimeGetCurrent() - t0];
    return YES;
}

- (void)stop {
    if (_rc) [_rc destroyRemoteCall];
    _rc = nil;
    _scratch = 0;
    _battle = 0;
    _battleKlass = 0;
    _w2sMethod = 0;
    _hasProjection = NO;
    self.ready = NO;
    self.running = NO;
    self.lastPlayerCount = 0;
    [self log:@"已停止"];
}

#pragma mark - il2cpp 符号解析

- (BOOL)resolveIl2Cpp {
    struct { const char *name; uint64_t *slot; } table[] = {
        { "il2cpp_domain_get",                  &_fn_domain_get },
        { "il2cpp_domain_assembly_open",        &_fn_domain_assembly_open },
        { "il2cpp_assembly_get_image",          &_fn_assembly_get_image },
        { "il2cpp_class_from_name",             &_fn_class_from_name },
        { "il2cpp_class_get_field_from_name",   &_fn_class_get_field_from_name },
        { "il2cpp_field_static_get_value",      &_fn_field_static_get_value },
        { "il2cpp_class_get_method_from_name",  &_fn_class_get_method_from_name },
        { "il2cpp_runtime_invoke",              &_fn_runtime_invoke },
    };

    int missing = 0;
    for (size_t i = 0; i < sizeof(table)/sizeof(table[0]); i++) {
        uint64_t addr = [self remoteDlsym:table[i].name];
        if (!addr) {
            [self log:@"符号缺失：%s", table[i].name];
            missing++;
            continue;
        }
        *table[i].slot = addr;
        [self log:@"%s -> 0x%llx", table[i].name, addr];
    }

    if (!_fn_domain_get || !_fn_class_from_name || !_fn_field_static_get_value) {
        [self log:@"关键符号缺失 %d 个，无法继续", missing];
        return NO;
    }
    return YES;
}

#pragma mark - 类 / 静态字段

- (uint64_t)findClass:(const char *)cls inAssembly:(const char *)asmName ns:(const char *)nsName {
    uint64_t domain = [self call:_fn_domain_get args:NULL count:0];
    if (!domain) { [self log:@"domain 为空"]; return 0; }

    [self writeStr:asmName at:_scratch];
    uint64_t a1[2] = { domain, _scratch };
    uint64_t asm_ = [self call:_fn_domain_assembly_open args:a1 count:2];
    if (!asm_) { [self log:@"找不到程序集 %s", asmName]; return 0; }

    uint64_t a2[1] = { asm_ };
    uint64_t image = [self call:_fn_assembly_get_image args:a2 count:1];
    if (!image) { [self log:@"image 为空"]; return 0; }

    [self writeStr:nsName  at:_scratch];
    [self writeStr:cls     at:_scratch + 128];
    uint64_t a3[3] = { image, _scratch, _scratch + 128 };
    uint64_t klass = [self call:_fn_class_from_name args:a3 count:3];
    if (!klass) [self log:@"找不到类 %s (程序集 %s)", cls, asmName];
    return klass;
}

- (uint64_t)staticField:(uint64_t)klass name:(const char *)fieldName {
    if (!klass) return 0;
    [self writeStr:fieldName at:_scratch];
    uint64_t a1[2] = { klass, _scratch };
    uint64_t field = [self call:_fn_class_get_field_from_name args:a1 count:2];
    if (!field) { [self log:@"静态字段 %s 不存在", fieldName]; return 0; }

    uint64_t outBuf = _scratch + 512;
    uint64_t a2[2] = { field, outBuf };
    [self call:_fn_field_static_get_value args:a2 count:2];
    return [_rc remoteRead64From:outBuf];
}

- (BOOL)resolveBattle {
    _battleKlass = [self findClass:ACE_CLASS_BATTLE inAssembly:ACE_ASSEMBLY ns:""];
    if (!_battleKlass) return NO;

    _battle = [self staticField:_battleKlass name:"Ins"];
    if (!_battle) {
        [self log:@"Battle.Ins 为空——必须在对局内（大厅可能没有实例）"];
        return NO;
    }
    [self log:@"Battle.Ins = 0x%llx", _battle];
    return YES;
}

#pragma mark - 相机投影

- (BOOL)resolveProjection {
    if (!_fn_class_get_method_from_name) return NO;

    uint64_t camKlass = [self findClass:ACE_UNITY_CAMERA_CLASS
                            inAssembly:ACE_UNITY_ASM
                                    ns:ACE_UNITY_CAMERA_NS];
    if (!camKlass) return NO;

    [self writeStr:"WorldToScreenPoint" at:_scratch];
    uint64_t a[3] = { camKlass, _scratch, 1 };   // 1 个参数
    _w2sMethod = [self call:_fn_class_get_method_from_name args:a count:3];
    if (!_w2sMethod) { [self log:@"WorldToScreenPoint 方法没找到"]; return NO; }
    return YES;
}

// 世界坐标 → 屏幕坐标
// 用 runtime_invoke：所有参数走内存，完全绕开浮点寄存器 ABI
- (CGPoint)worldToScreen:(uint64_t)cameraObj x:(float)x y:(float)y z:(float)z {
    if (!_hasProjection || !cameraObj || !_scratch) return CGPointZero;

    // 布局：+0x000 Vector3 入参 | +0x100 boxed 结果 | +0x200 exc | +0x300 params[1]
    float v3[3] = { x, y, z };
    [_rc remote_write:_scratch from:v3 size:12];

    uint64_t paramPtr = _scratch;                // params[0] 指向那个 Vector3
    [_rc remote_write:_scratch + 0x300 from:&paramPtr size:8];

    uint64_t zero = 0;
    [_rc remote_write:_scratch + 0x200 from:&zero size:8];

    uint64_t a[4] = { _w2sMethod, cameraObj, _scratch + 0x300, _scratch + 0x200 };
    uint64_t boxed = [self call:_fn_runtime_invoke args:a count:4];
    if (!boxed) return CGPointZero;

    // 检查异常槽，非 0 说明 invoke 抛了
    uint64_t exc = [_rc remoteRead64From:_scratch + 0x200];
    if (exc) return CGPointZero;

    // 装箱 Vector3：Il2CppObject{klass,monitor} + float x,y,z
    float out[3] = {0};
    [_rc remoteRead:boxed + OFF_IL2CPP_BOXED_VALUE to:out size:12];
    return CGPointMake(out[0], out[1]);
}

- (uint64_t)cameraObject {
    if (!_battle) return 0;
    uint64_t camComp = [_rc remoteRead64From:_battle + OFF_BATTLE_MAINCAMERA];
    if (!camComp) return 0;
    return [_rc remoteRead64From:camComp + OFF_V3CAM_CAMERA];
}

#pragma mark - 字符串

- (void)readString:(uint64_t)strObj into:(char *)dst size:(size_t)dstSize {
    dst[0] = '\0';
    if (!strObj || dstSize < 2) return;

    int32_t len = (int32_t)[_rc remoteRead64From:strObj + OFF_STR_LEN];
    if (len <= 0 || len > 128) return;
    if ((size_t)len > dstSize - 1) len = (int32_t)dstSize - 1;

    uint16_t buf[129] = {0};
    if (![_rc remoteRead:strObj + OFF_STR_CHARS to:buf size:(uint64_t)len * 2]) return;

    NSString *s = [[NSString alloc] initWithCharacters:buf length:len];
    if (s) strncpy(dst, s.UTF8String, dstSize - 1);
}

#pragma mark - 玩家扫描

- (int)scanPlayers:(AcePlayer *)outBuf maxCount:(int)maxCount {
    if (!self.ready || !_battle || !_rc) return 0;

    uint64_t dict = [_rc remoteRead64From:_battle + OFF_BATTLE_OTHERPLAYERSDIC];
    if (!dict) return 0;

    uint64_t entries = [_rc remoteRead64From:dict + OFF_DICT_ENTRIES];
    int32_t  count   = (int32_t)[_rc remoteRead64From:dict + OFF_DICT_COUNT];
    if (!entries || count <= 0) return 0;

    int out = 0;
    for (int i = 0; i < count && out < maxCount; i++) {
        uint64_t e = entries + (uint64_t)i * DICT_ENTRY_SIZE;

        int32_t hc = (int32_t)[_rc remoteRead64From:e];
        if (hc < 0) continue;                                  // 空槽

        uint64_t opc = [_rc remoteRead64From:e + DICT_ENTRY_VALUE];
        if (!opc) continue;

        // 过滤虚拟玩家（诱饵）
        if ([_rc remoteRead64From:opc + OFF_OPC_ISVIRTUAL] & 0xFF) continue;

        AcePlayer p; memset(&p, 0, sizeof(p));
        p.controller = opc;

        // WorldPos 是内联 Vector3，直接读 12 字节
        [_rc remoteRead:opc + OFF_OPC_WORLDPOS to:&p.x size:12];

        uint64_t info = [_rc remoteRead64From:opc + OFF_OPC_INFO];
        if (info) {
            p.hp      = (int32_t)[_rc remoteRead64From:info + OFF_PI_HP];
            p.hpMax   = (int32_t)[_rc remoteRead64From:info + OFF_PI_HPMAX];
            p.groupId = (int32_t)[_rc remoteRead64From:info + OFF_PI_GROUPID];
            p.roleId  = (int64_t)[_rc remoteRead64From:info + OFF_PI_ROLEID];
            p.status  = (uint8_t)([_rc remoteRead64From:info + OFF_PI_CURSTATUS] & 0xFF);
            [self readString:[_rc remoteRead64From:info + OFF_PI_NAME]
                        into:p.name size:sizeof(p.name)];
        }

        if (p.status == ACE_ST_DIE) continue;                   // 死人不要

        outBuf[out++] = p;
    }

    self.lastPlayerCount = out;
    return out;
}

#pragma mark - 验证输出

- (void)dumpOnce {
    if (!self.ready) { [self log:@"未就绪，先 start"]; return; }

    AcePlayer buf[ACE_MAX_PLAYERS];
    int n = [self scanPlayers:buf maxCount:ACE_MAX_PLAYERS];

    [self log:@"========== 扫描到 %d 个玩家 ==========", n];
    for (int i = 0; i < n; i++) {
        AcePlayer *p = &buf[i];
        [self log:@"[%02d] %@ hp=%d/%d team=%d st=%d pos=(%.1f, %.1f, %.1f) opc=0x%llx",
              i,
              p->name[0] ? [NSString stringWithUTF8String:p->name] : @"(无名)",
              p->hp, p->hpMax, p->groupId, p->status,
              p->x, p->y, p->z, p->controller];
    }
    if (n == 0) {
        [self log:@"-- 0 个。依次检查：是否在局内 / 进程名 / 偏移是否过期 --"];
    }
}

#pragma mark - 排查工具

- (NSArray<NSString *> *)listProcesses {
    if (!ds_is_ready()) {
        [self log:@"内核未就绪，列不了进程"];
        return @[];
    }
    int n = 0;
    proc_entry_t *list = proclist(NULL, &n);
    if (!list) {
        [self log:@"proclist 返回空（内核读写可能有问题）"];
        return @[];
    }
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        char nm[33] = {0};
        memcpy(nm, list[i].name, 32);
        [out addObject:[NSString stringWithFormat:@"%s (pid=%u)", nm, list[i].pid]];
    }
    free_proclist(list);
    [self log:@"共 %d 个进程", n];
    return out;
}

- (NSArray<NSString *> *)searchProcesses:(NSString *)keyword {
    if (!ds_is_ready() || keyword.length == 0) return @[];
    int n = 0;
    proc_entry_t *list = proclist(keyword.UTF8String, &n);
    if (!list) return @[];
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        char nm[33] = {0};
        memcpy(nm, list[i].name, 32);
        [out addObject:[NSString stringWithFormat:@"%s (pid=%u)", nm, list[i].pid]];
    }
    free_proclist(list);
    return out;
}

/// 用户填错名字时，从输入里猜关键词，去进程表里找相近的
- (void)suggestFor:(NSString *)input {
    [self log:@"正在按关键词搜索进程…"];

    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    for (NSString *seg in [input componentsSeparatedByString:@"."]) {
        if (seg.length >= 3) [keys addObject:seg];
    }
    // 也用完整输入试一次
    if (input.length >= 3) [keys addObject:input];

    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    BOOL found = NO;
    for (NSString *k in keys) {
        for (NSString *hit in [self searchProcesses:k]) {
            if ([seen containsObject:hit]) continue;
            [seen addObject:hit];
            [self log:@"  命中[%@] → %@", k, hit];
            found = YES;
        }
    }

    if (!found) {
        [self log:@"  没找到相近进程。改用「列出进程」按钮翻一遍完整列表"];
    }
}

#pragma mark - Overlay / WebSocket

- (void)startOverlayAsync:(void (^)(BOOL))completion {
    dispatch_async(_espQueue, ^{
        BOOL ok = [self startOverlay];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(ok);
        });
    });
}

- (BOOL)startOverlay {
    if (!self.ready || !_rc) { [self log:@"先成功启动 ESP，再开绘制"]; return NO; }

    __weak typeof(self) weakSelf = self;

    // 1) 本机 WebSocket 服务端
    if (!_ws) _ws = [AceWS new];
    _ws.onLog = ^(NSString *s) { [weakSelf log:@"%@", s]; };
    _ws.onMessage = ^(NSString *role, NSDictionary *msg) { [weakSelf handleWS:role msg:msg]; };
    if (![_ws start]) { [self log:@"WebSocket 启动失败"]; return NO; }

    // 2) 在游戏进程里建 WebView
    if (!_overlay) _overlay = [AceOverlay new];
    BOOL ok = [_overlay installWithRemoteCall:_rc
                                       wsPort:_ws.port
                                     logBlock:^(NSString *s) { [weakSelf log:@"%@", s]; }];
    if (!ok) { [self log:@"overlay 安装失败"]; return NO; }

    self.drawing = YES;
    [self startRenderLoop];
    [self log:@"绘制已开启，前端连 ws://127.0.0.1:%u", _ws.port];
    return YES;
}

- (void)stopOverlayAsync {
    dispatch_async(_espQueue, ^{ [self stopOverlay]; });
}

- (void)stopOverlay {
    [self stopRenderLoop];
    [_overlay uninstall];
    _overlay = nil;
    [_ws stop];
    _ws = nil;
    self.drawing = NO;
    [self log:@"绘制已关闭"];
}

- (void)handleWS:(NSString *)role msg:(NSDictionary *)msg {
    NSString *type = msg[@"type"];
    if ([type isEqualToString:@"viewport"]) {
        [self log:@"前端上报 viewport %@ x %@", msg[@"width"], msg[@"height"]];
    }
}

#pragma mark - 渲染循环

- (void)startRenderLoop {
    [self stopRenderLoop];
    // 8Hz —— 每个 worldToScreen 都是一次跨进程调用，频率再高会把目标进程拖死
    _renderTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _espQueue);
    dispatch_source_set_timer(_renderTimer,
                              dispatch_time(DISPATCH_TIME_NOW, 0),
                              125ull * NSEC_PER_MSEC,
                              20ull * NSEC_PER_MSEC);
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_renderTimer, ^{ [weakSelf renderFrame]; });
    dispatch_resume(_renderTimer);
}

- (void)stopRenderLoop {
    if (_renderTimer) {
        dispatch_source_cancel(_renderTimer);
        _renderTimer = nil;
    }
}

- (void)renderFrame {
    if (!self.drawing || !_overlay || !_overlay.installed || !_ws) return;

    AcePlayer buf[ACE_MAX_PLAYERS];
    int n = [self scanPlayers:buf maxCount:ACE_MAX_PLAYERS];
    CGSize sz = _overlay.screenSize;
    uint64_t cam = [self cameraObject];

    NSMutableArray *targets = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AcePlayer *p = &buf[i];

        CGPoint sp = CGPointZero;
        if (cam) sp = [self worldToScreen:cam x:p->x y:p->y z:p->z];

        BOOL onScreen = (sp.x >= 0 && sp.y >= 0 && sp.x <= sz.width && sp.y <= sz.height);

        // 包围盒：固定尺寸起步，后面换成按距离缩放
        float h = 140.0f;
        float w = h * 0.45f;

        NSDictionary *e = @{
            @"visible"      : @YES,
            @"onScreen"     : @(onScreen),
            @"sx"           : @(sp.x),
            @"sy"           : @(sp.y),
            @"hp"           : @(p->hp),
            @"maxHp"        : @(p->hpMax > 0 ? p->hpMax : 100),
            @"name"         : p->name[0] ? [NSString stringWithUTF8String:p->name] : @"",
            @"distance"     : @0,
            @"box"          : @{ @"x": @(sp.x - w/2), @"y": @(sp.y - h/2),
                                 @"w": @(w), @"h": @(h) },
            @"drawBox"      : @(self.optBox),
            @"drawLine"     : @(self.optLine),
            @"drawName"     : @(self.optName),
            @"drawHealth"   : @(self.optHealth),
            @"drawDistance" : @(self.optDistance),
        };
        [targets addObject:e];
    }

    [_ws send:@{ @"type": @"targets", @"targets": targets } toRole:@"esp"];
    self.lastTargetCount = (int)targets.count;
}

@end
