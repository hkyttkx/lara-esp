//
//  AceWS.h
//  Overlay WebSocket 服务端（跑在本 App 进程内）
//
//  为什么需要它：overlay 的 WKWebView 建在【目标游戏进程】里，
//  而读内存、算坐标在【本 App 进程】里。两个进程之间用本地回环
//  ws://127.0.0.1:PORT 通信，比每帧 evaluateJavaScript 便宜得多。
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AceWS : NSObject

/// 开始监听（端口自动分配）。返回是否成功。
- (BOOL)start;
- (void)stop;

/// 实际监听端口
@property (nonatomic, readonly) uint16_t port;

/// 广播 JSON 给指定角色的客户端（role 传 nil 表示全部）
- (void)send:(NSDictionary *)obj toRole:(nullable NSString *)role;

/// 客户端消息回调（已在后台线程，自行切主线程）
@property (nonatomic, copy, nullable) void (^onMessage)(NSString *role, NSDictionary *msg);

/// 日志
@property (nonatomic, copy, nullable) void (^onLog)(NSString *line);

/// 已连接客户端数
@property (nonatomic, readonly) NSUInteger clientCount;

@end

NS_ASSUME_NONNULL_END
