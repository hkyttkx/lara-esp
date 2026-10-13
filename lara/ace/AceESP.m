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
#import "../kexploit/offsets.h"
#import "../kexploit/utils.h"
#import "../kexploit/TaskRop/RemoteCall.h"
#import "../kexploit/TaskRop/pac.h"

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

    // 先用 procbyname 验证目标进程真的存在。
    // 注意：proclist() 在某些固件上不可靠（allproc 起点是坏的），
    // 但 procbyname() 走 kernproc 链，是可信的。
    if (_targetProcess.length == 0) {
        [self log:@"目标进程名为空"];
        return NO;
    }
    uint64_t targetProc = procbyname(_targetProcess.UTF8String);
    if (!targetProc) {
        [self log:@"procbyname('%@') 没找到 → 进程名不对，或游戏没在跑", _targetProcess];
        [self log:@"提示：进程名是可执行文件名，不是 Bundle ID。用列表按钮查"];
        [self suggestFor:_targetProcess];
        return NO;
    }
    [self log:@"procbyname('%@') = 0x%llx ✅ 进程存在", _targetProcess, targetProc];

    _rc = [[RemoteCall alloc] initWithProcess:_targetProcess useMigFilterBypass:NO];
    if (!_rc) {
        [self log:@"连接进程失败：%@", [RemoteCall lastInitError]];
        [self log:@"注意：这里要填【进程名 / 可执行文件名】，不是 Bundle ID"];
        [self suggestFor:_targetProcess];
        return NO;
    }
    // DarkSpeed 同款校验：初始化返回非 nil 不代表可用
    if (!_rc.trojanMem || _rc.pid <= 1) {
        [self log:@"⚠️ RemoteCall 返回了对象但不可用：trojanMem=0x%llx pid=%d",
              _rc.trojanMem, _rc.pid];
        [self log:@"   这通常意味着内核原语或线程注入没真正建立"];
        [_rc destroyRemoteCall];
        _rc = nil;
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

#pragma mark - 内核自检

- (void)diagnoseAsync {
    dispatch_async(_espQueue, ^{ [self diagnose]; });
}

- (void)diagnose {
    [self log:@"========== 内核自检 =========="];

    if (!ds_is_ready()) {
        [self log:@"ds_is_ready = NO → kexploit 没跑起来"];
        return;
    }
    [self log:@"ds_is_ready = YES"];

    uint64_t kbase = ds_get_kernel_base();
    [self log:@"kernel_base = 0x%llx", kbase];

    // 黄金标准：内核 mach_header 的 magic 必须是 0xfeedfacf
    uint32_t magic = kbase ? ds_kread32(kbase) : 0;
    [self log:@"magic @ kbase = 0x%x", magic];
    if (magic == 0xfeedfacf) {
        [self log:@"  ✅ 内核读正确"];
    } else {
        [self log:@"  ❌ 内核读错误（应为 0xfeedfacf）—— 这就是扫不到进程的根因"];
    }

    uint32_t myPid = (uint32_t)getpid();
    uint64_t proc = ourproc();
    [self log:@"ourproc = 0x%llx %@", proc, proc ? @"✅" : @"❌"];
    if (proc) {
        // PROC_PID_OFFSET 只定义在 utils.m 内部，这里用 offsets.h 导出的值
        uint32_t pidOff = off_proc_p_pid ? off_proc_p_pid : 0x60;
        uint32_t pid = ds_kread32(proc + pidOff);
        [self log:@"our pid = %u（应为 %u，偏移 0x%x）%@",
              pid, myPid, pidOff, pid == myPid ? @"✅" : @"❌"];
        uint64_t task = taskbyproc(proc);
        [self log:@"ourtask = 0x%llx %@", task, task ? @"✅" : @"❌"];
    }

    const char *selfName = getprogname();
    if (selfName) {
        uint64_t byName = procbyname(selfName);
        [self log:@"procbyname(%s) = 0x%llx %@", selfName, byName, byName ? @"✅" : @"❌"];
    }

    int n = 0;
    proc_entry_t *list = proclist(NULL, &n);
    [self log:@"proclist 数量 = %d（正常 200+）%@", n,
          n > 50 ? @"✅" : @"❌ 链表遍历断了"];
    if (list) {
        int show = n < 8 ? n : 8;
        for (int i = 0; i < show; i++) {
            [self log:@"  [%d] '%s' pid=%u kaddr=0x%llx",
                  i, list[i].name, list[i].pid, list[i].kaddr];
        }
        free_proclist(list);
    }

    [self log:@"==============================="];
}

#pragma mark - 注入对照测试

- (void)testInjectSelfAsync {
    dispatch_async(_espQueue, ^{ [self testInjectSelf]; });
}

/// 判断"游戏注入失败"是不是因为进程被挂起：
/// lara 自己此刻在前台、线程活跃 —— 如果它也不能注入，说明不是挂起问题；
/// 如果能注入，就把「活跃 = 可注入 / 后台挂起 = 不可注入」这条规律钉死。
- (void)testInjectSelf {
    [self log:@"===== 注入对照：lara 自己（前台活跃）====="];

    if (!ds_is_ready()) { [self log:@"内核未就绪"]; return; }

    const char *selfName = getprogname();
    [self log:@"本进程名 = %s (pid=%d)", selfName ?: "?", getpid()];

    uint64_t p = procbyname(selfName);
    [self log:@"procbyname('%s') = 0x%llx %@", selfName, p, p ? @"✅" : @"❌"];
    if (!p) return;

    RemoteCall *rc = [[RemoteCall alloc] initWithProcess:[NSString stringWithUTF8String:selfName]
                                       useMigFilterBypass:NO];
    if (!rc) {
        [self log:@"❌ 连自己都失败：%@", [RemoteCall lastInitError]];
        [self log:@"→ 说明不是「后台挂起」，是更底层的问题"];
        return;
    }
    if (!rc.trojanMem || rc.pid <= 1) {
        [self log:@"❌ 返回对象但不可用 trojanMem=0x%llx pid=%d", rc.trojanMem, rc.pid];
        [rc destroyRemoteCall];
        return;
    }

    [self log:@"✅ 注入自己成功 pid=%d trojanMem=0x%llx", rc.pid, rc.trojanMem];
    [self log:@"→ 前台活跃进程可注入。游戏失败因此指向「后台被挂起」"];
    [rc destroyRemoteCall];
    [self log:@"=========================================="];
}

#pragma mark - 挂起状态诊断

- (void)diagnoseSuspendAsync {
    dispatch_async(_espQueue, ^{ [self diagnoseSuspend]; });
}

/// 只读扫一遍：比较 lara（前台）和游戏（后台）的 task 结构，
/// 找出值很小的、且两者不同的整数 —— suspend_count 就在这些候选里。
/// ⚠️ 这里不写内存，只做定位。
- (void)diagnoseSuspend {
    [self log:@"===== 挂起状态诊断 ====="];
    if (!ds_is_ready()) { [self log:@"内核未就绪"]; return; }

    uint64_t selfProc = ourproc();
    uint64_t selfTask = selfProc ? taskbyproc(selfProc) : 0;
    [self log:@"lara(前台) proc=0x%llx task=0x%llx", selfProc, selfTask];

    uint64_t gameProc = procbyname("sc");
    if (!gameProc) { [self log:@"进程 'sc' 不存在 —— 把游戏打开再试"]; return; }
    uint64_t gameTask = taskbyproc(gameProc);
    [self log:@"sc(后台)   proc=0x%llx task=0x%llx", gameProc, gameTask];

    if (!selfTask || !gameTask) { [self log:@"task 地址拿不到"]; return; }

    [self log:@"--- 候选字段（值 <= 16 且两者不同）---"];
    int hits = 0;
    for (uint32_t off = 0; off < 0x400; off += 4) {
        uint32_t a = ds_kread32(selfTask + off);
        uint32_t b = ds_kread32(gameTask + off);
        if (a > 16 || b > 16) continue;
        if (a == b) continue;
        [self log:@"  +0x%03x   lara=%u   sc=%u", off, a, b];
        hits++;
    }
    [self log:@"--- 共 %d 个候选 ---", hits];
    [self log:@"差值为 1 的那个最可能是 suspend_count"];
    [self log:@"==============================="];
}

#pragma mark - PAC 诊断

/// 线程注入失败（Remote call faulted at getpid entry pc=0x201）的直接原因排查：
/// signState 里 remotepac 签名失败会退回未签名 PC，PC 就停在 0x201 这个 trap 值上。
/// remotepac 依赖 findpacia() 找到 pacia gadget，而 findpacia 又依赖一个写死的
/// Swift 符号 "$sSwySWSnySiGciM" —— 那个符号在不同 iOS 版本上不保证存在。
- (void)diagnosePACAsync {
    dispatch_async(_espQueue, ^{ [self diagnosePAC]; });
}

- (void)diagnosePAC {
    [self log:@"========== PAC 诊断 =========="];

    [self log:@"is_pac_supported = %@", is_pac_supported() ? @"YES" : @"NO"];
    [self log:@"pacsignworks()   = %@", pacsignworks() ? @"YES" : @"NO"];

    void *pacSym = dlsym(RTLD_DEFAULT, "$sSwySWSnySiGciM");
    if (pacSym) {
        [self log:@"dlsym($sSwySWSnySiGciM) = %p ✅ 存在", pacSym];
    } else {
        [self log:@"dlsym($sSwySWSnySiGciM) = NULL ❌"];
        [self log:@"  → findpacia() 必然返回 0，remotepac() 必然返回 -1"];
        [self log:@"  → 线程注入必然失败，PC 停在 0x201"];
        [self log:@"  这就是根因，与游戏、进程名、权限都无关"];
    }

    uint64_t gadget = findpacia();
    [self log:@"findpacia() = 0x%llx %@", gadget, gadget ? @"✅ gadget 可用" : @"❌ gadget 没找到"];

    [self log:@"==============================="];
}

#pragma mark - 内核偏移准备

- (void)prepareOffsetsAsync {
    dispatch_async(_espQueue, ^{ [self prepareOffsets]; });
}

- (void)prepareOffsets {
    [self log:@"========== 准备内核偏移 =========="];

    NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = dirs.firstObject;
    if (!docs) { [self log:@"拿不到 Documents 目录"]; return; }

    NSString *kc = [docs stringByAppendingPathComponent:@"kernelcache"];
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL exists = [fm fileExistsAtPath:kc];

    [self log:@"kernelcache 路径: %@", kc];
    if (!exists) {
        [self log:@"状态：❌ 不存在 —— 这就是偏移全空、进程表读不出来的原因"];
    } else {
        NSDictionary *attrs = [fm attributesOfItemAtPath:kc error:nil];
        double mb = [attrs[NSFileSize] doubleValue] / 1048576.0;
        [self log:@"状态：已存在（%.1f MB）", mb];

        NSFileHandle *h = [NSFileHandle fileHandleForReadingAtPath:kc];
        NSData *d = [h readDataOfLength:2];
        [h closeFile];
        if (d.length == 2) {
            const uint8_t *b = d.bytes;
            [self log:@"头部: %02x %02x  %@", b[0], b[1],
                  (b[0] == 0x30 && b[1] == 0x84) ? @"✅ 有效 im4p" : @"⚠️ 格式可疑"];
        }
        if (mb < 1.0) {
            [self log:@"⚠️ 文件过小，可能是半截下载，先删掉重来"];
            [fm removeItemAtPath:kc error:nil];
            [self log:@"已删除，重新下载…"];
        }
    }

    [self log:@"调用 dlkcache()（下载 + 解析）…可能需要几分钟"];
    CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
    BOOL ok = dlkcache();
    [self log:@"dlkcache() = %@  耗时 %.1fs", ok ? @"✅ 成功" : @"❌ 失败",
          CFAbsoluteTimeGetCurrent() - t0];

    if (ok) {
        [self log:@"偏移已就位。回到上面重新点「启动 ESP」即可"];
    } else {
        [self log:@"失败。可能原因：网络不通 / Apple 服务器上找不到匹配固件的 kernelcache"];
        [self log:@"备选：手动把 kernelcache 放进 lara 的 Documents 目录"];
    }
    [self log:@"=================================="];
}

#pragma mark - SpringBoard 对照测试

- (void)testSpringBoardAsync {
    dispatch_async(_espQueue, ^{ [self testSpringBoard]; });
}

/// DarkSpeed 就是连 SpringBoard 的（而且它工作正常），所以这里当基准对照：
/// 如果 SpringBoard 能连、目标游戏不能 → 问题是游戏进程本身（保护/特性）
/// 如果 SpringBoard 也连不上 → 问题是 RemoteCall 或内核原语
- (void)testSpringBoard {
    [self log:@"===== SpringBoard 对照测试 ====="];

    if (!ds_is_ready()) {
        [self log:@"内核未就绪"];
        return;
    }

    uint64_t p = procbyname("SpringBoard");
    [self log:@"procbyname('SpringBoard') = 0x%llx %@", p, p ? @"✅" : @"❌"];
    if (!p) return;

    RemoteCall *rc = [[RemoteCall alloc] initWithProcess:@"SpringBoard"
                                       useMigFilterBypass:NO];
    if (!rc) {
        [self log:@"❌ 连接失败：%@", [RemoteCall lastInitError]];
        [self log:@"→ RemoteCall 本身有问题，不是游戏的事"];
        return;
    }
    [self log:@"✅ 连上了！pid=%d trojanMem=0x%llx", rc.pid, rc.trojanMem];
    [self log:@"→ RemoteCall 可用，问题在目标游戏进程"];

    [rc destroyRemoteCall];
    [self log:@"==============================="];
}

#pragma mark - Overlay / WebSocket

- (void)startOverlayAsync:(void (^)(BOOL))completion {    dispatch_async(_espQueue, ^{
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
