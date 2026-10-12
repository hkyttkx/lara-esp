//
//  AceESP.h
//  王牌战争 ESP — 数据层接口
//
//  用法：
//      AceESP *esp = [AceESP shared];
//      esp.targetProcess = @"AceForce";
//      if ([esp start]) {
//          [esp dumpOnce];
//      }
//
#import <Foundation/Foundation.h>
#import <stdint.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

/// 一个玩家的快照（纯值类型，可跨线程传递）
typedef struct {
    uint64_t controller;        // OtherPlayerController 远程地址
    int64_t  roleId;
    int32_t  hp;
    int32_t  hpMax;
    int32_t  groupId;           // 阵营；与自己相同 = 队友
    uint8_t  status;            // ACE_ST_* 常量
    float    x, y, z;           // 世界坐标
    char     name[64];          // UTF-8
} AcePlayer;

@interface AceESP : NSObject

+ (instancetype)shared;

#pragma mark - 配置
@property (nonatomic, copy)   NSString *targetProcess;
@property (nonatomic, assign) BOOL      ready;
@property (nonatomic, assign) BOOL      running;
@property (nonatomic, assign) int       lastPlayerCount;

/// 日志回调（后台线程调用，UI 侧自行切主线程）
@property (nonatomic, copy, nullable) void (^logBlock)(NSString *line);

#pragma mark - 生命周期
/// 完整初始化：内核检查 → 连进程 → 解析 il2cpp → 取 Battle.Ins
- (BOOL)start;
/// 停止：只清状态，不杀进程
- (void)stop;

#pragma mark - 数据
/// 拉一次玩家快照，返回实际写入数量
- (int)scanPlayers:(AcePlayer *)outBuf maxCount:(int)maxCount;
/// 把当前玩家列表打到日志（第一步验证用）
- (void)dumpOnce;

@end

NS_ASSUME_NONNULL_END
