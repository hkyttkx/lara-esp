//
//  AceOverlay.h
//  跨进程 overlay — 在目标进程里建 WKWebView 挂到游戏窗口上
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class RemoteCall;

NS_ASSUME_NONNULL_BEGIN

@interface AceOverlay : NSObject

/// 在目标进程内建好 WKWebView 并挂到游戏 UIWindow
- (BOOL)installWithRemoteCall:(RemoteCall *)rc logBlock:(nullable void (^)(NSString *))logBlock;

/// 推一帧给 JS。每个元素用 NSString/NSNumber 组成字典
- (void)pushEntities:(NSArray<NSDictionary *> *)entities;

/// 拆掉 overlay（反复测试必须调用，否则游戏进程内存里会累积窗口）
- (void)uninstall;

@property (nonatomic, readonly) BOOL    installed;
@property (nonatomic, readonly) CGSize  screenSize;   // 游戏窗口尺寸（横屏宽>高）
@property (nonatomic, readonly) uint64_t webView;

@end

NS_ASSUME_NONNULL_END
