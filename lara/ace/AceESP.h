//
//  AceESP.h
//  王牌战争 ESP — 数据层 + overlay
//
#import <Foundation/Foundation.h>
#import <stdint.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

/// 一个玩家的快照（纯值类型，可跨线程传递）
typedef struct {
    uint64_t controller;
    int64_t  roleId;
    int32_t  hp;
    int32_t  hpMax;
    int32_t  groupId;
    uint8_t  status;
    float    x, y, z;
    char     name[64];
} AcePlayer;

@interface AceESP : NSObject

+ (instancetype)shared;

#pragma mark - 配置
@property (nonatomic, copy)   NSString *targetProcess;
@property (nonatomic, assign) BOOL      ready;
@property (nonatomic, assign) BOOL      running;
@property (nonatomic, assign) BOOL      drawing;      // overlay 是否在跑
@property (nonatomic, assign) int       lastPlayerCount;
@property (nonatomic, assign) int       lastTargetCount;   // 本帧推给前端的实体数

/// 绘制开关（对应前端 entity.drawXxx）
@property (nonatomic, assign) BOOL optBox;
@property (nonatomic, assign) BOOL optLine;
@property (nonatomic, assign) BOOL optName;
@property (nonatomic, assign) BOOL optHealth;
@property (nonatomic, assign) BOOL optDistance;

@property (nonatomic, copy, nullable) void (^logBlock)(NSString *line);

#pragma mark - 生命周期
/// 同步初始化（只允许在内部串行队列上调用）
- (BOOL)start;
/// 异步启动。completion 回主线程。
- (void)startAsync:(void (^)(BOOL ok))completion;
- (void)stop;

/// 开启绘制：启动 WebSocket 服务端 + 在游戏进程建 overlay
- (void)startOverlayAsync:(void (^)(BOOL ok))completion;
- (void)stopOverlayAsync;

#pragma mark - 数据
- (int)scanPlayers:(AcePlayer *)outBuf maxCount:(int)maxCount;
- (void)dumpOnce;
- (void)dumpOnceAsync;

#pragma mark - 排查工具
- (NSArray<NSString *> *)listProcesses;
- (NSArray<NSString *> *)searchProcesses:(NSString *)keyword;
- (void)listProcessesAsync;
/// 内核读写自检：验证 kexploit 拿到的原语是否真的可靠
- (void)diagnoseAsync;
/// 准备内核偏移：下载/解析 kernelcache（缺失时 lara 所有偏移都是空的）
- (void)prepareOffsetsAsync;

@end

NS_ASSUME_NONNULL_END
