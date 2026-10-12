//
//  AceOverlay.h
//  跨进程 overlay —— 在【目标游戏进程】里建 WKWebView
//
//  走的样本那套架构：
//      本 App 进程：读内存 + 算屏幕坐标 + AceWS 广播
//      游戏进程  ：WKWebView 连 ws://127.0.0.1:PORT → Canvas 画
//
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class RemoteCall;

NS_ASSUME_NONNULL_BEGIN

@interface AceOverlay : NSObject

/// 在目标进程里建 overlay WebView 并挂到游戏窗口。
/// wsPort 会被注入 HTML，WebView 里用它连回本 App 的 AceWS。
- (BOOL)installWithRemoteCall:(RemoteCall *)rc
                       wsPort:(uint16_t)wsPort
                     logBlock:(nullable void (^)(NSString *))logBlock;

/// 拆掉 overlay（反复测试必须调用）
- (void)uninstall;

/// 额外挂一个 WebView（菜单 / 悬浮按钮），role 对应 HTML 里的角色名
- (BOOL)attachAuxWebView:(RemoteCall *)rc role:(NSString *)role
                    html:(NSString *)html logBlock:(nullable void (^)(NSString *))logBlock;

@property (nonatomic, readonly) BOOL      installed;
@property (nonatomic, readonly) CGSize    screenSize;
@property (nonatomic, readonly) uint64_t  webView;

@end

NS_ASSUME_NONNULL_END
