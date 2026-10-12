//
//  AceOverlay.m
//  在目标游戏进程里建 WKWebView overlay
//
//  流程：找游戏 UIWindow → 目标进程内 alloc WKWebView
//        → initWithFrame: → loadHTMLString: → addSubview:
//
#import "AceOverlay.h"
#import "AceOffsets.h"
#import "ace_html.h"
#import "../kexploit/TaskRop/RemoteCall.h"

#import <objc/runtime.h>
#import <stdarg.h>

@implementation AceOverlay {
    RemoteCall *_rc;
    uint64_t    _win;
    void (^_log)(NSString *);
}

#pragma mark - 日志

- (void)log:(NSString *)fmt, ... {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[OVL] %@", s);
    if (_log) _log(s);
}

#pragma mark - ObjC 跨进程小工具

- (uint64_t)send:(uint64_t)obj sel:(const char *)name {
    return remote_msg(_rc, obj, remote_sel(_rc, name), 0, 0, 0, 0);
}
- (uint64_t)send:(uint64_t)obj sel:(const char *)name a0:(uint64_t)a0 {
    return remote_msg(_rc, obj, remote_sel(_rc, name), a0, 0, 0, 0);
}
- (uint64_t)send:(uint64_t)obj sel:(const char *)name a0:(uint64_t)a0 a1:(uint64_t)a1 {
    return remote_msg(_rc, obj, remote_sel(_rc, name), a0, a1, 0, 0);
}

#pragma mark - 找游戏窗口

- (uint64_t)findGameWindow {
    uint64_t appCls = remote_getClass(_rc, "UIApplication");
    if (!appCls) { [self log:@"拿不到 UIApplication 类"]; return 0; }

    uint64_t app = [self send:appCls sel:"sharedApplication"];
    if (!app) { [self log:@"sharedApplication 为空"]; return 0; }

    uint64_t scenes = [self send:app sel:"connectedScenes"];
    if (scenes) {
        uint64_t arr = [self send:scenes sel:"allObjects"];
        uint64_t nScenes = arr ? [self send:arr sel:"count"] : 0;

        for (uint64_t i = 0; i < nScenes; i++) {
            uint64_t scene = remote_msg(_rc, arr, remote_sel(_rc, "objectAtIndex:"), i, 0, 0, 0);
            if (!scene) continue;

            uint64_t wins = [self send:scene sel:"windows"];
            uint64_t nWins = wins ? [self send:wins sel:"count"] : 0;
            if (nWins == 0) continue;

            uint64_t fallback = 0;
            for (uint64_t j = 0; j < nWins; j++) {
                uint64_t w = remote_msg(_rc, wins, remote_sel(_rc, "objectAtIndex:"), j, 0, 0, 0);
                if (!w) continue;
                if (!fallback) fallback = w;
                if ([self send:w sel:"isHidden"] == 0) {
                    [self log:@"找到可见窗口 @ 0x%llx", w];
                    return w;
                }
            }
            if (fallback) {
                [self log:@"无可见窗口，用兜底 @ 0x%llx", fallback];
                return fallback;
            }
        }
    }

    uint64_t kw = [self send:app sel:"keyWindow"];
    if (kw) { [self log:@"兜底 keyWindow @ 0x%llx", kw]; return kw; }

    [self log:@"没找到任何窗口"];
    return 0;
}

#pragma mark - 建 WebView

- (uint64_t)createWebView:(CGRect)frame {
    uint64_t wvCls = remote_getClass(_rc, "WKWebView");
    if (!wvCls) { [self log:@"WKWebView 类拿不到"]; return 0; }

    uint64_t wv = [self send:wvCls sel:"alloc"];
    if (!wv) { [self log:@"WKWebView alloc 失败"]; return 0; }

    // initWithFrame: 单 CGRect 参数，正好用 remote_setCGRect
    remote_setCGRect(_rc, wv, remote_sel(_rc, "initWithFrame:"), frame);

    // 透明 + 不吃触摸
    uint64_t clear = [self send:remote_getClass(_rc, "UIColor") sel:"clearColor"];
    [self send:wv sel:"setOpaque:" a0:0];
    [self send:wv sel:"setUserInteractionEnabled:" a0:0];
    [self send:wv sel:"setBackgroundColor:" a0:clear];

    uint64_t sv = [self send:wv sel:"scrollView"];
    if (sv) {
        [self send:sv sel:"setScrollEnabled:" a0:0];
        [self send:sv sel:"setBackgroundColor:" a0:clear];
        [self send:sv sel:"setUserInteractionEnabled:" a0:0];
    }

    [self log:@"WebView 创建完成 @ 0x%llx  %.0fx%.0f",
          wv, frame.size.width, frame.size.height];
    return wv;
}

- (void)loadHTML:(NSString *)html into:(uint64_t)wv {
    uint64_t rHTML = remote_NSString(_rc, html.UTF8String);
    uint64_t rBase = remote_NSString(_rc, "about:blank");
    if (!rHTML) { [self log:@"远程 HTML 字符串创建失败"]; return; }
    [self send:wv sel:"loadHTMLString:baseURL:" a0:rHTML a1:rBase];
    [self log:@"HTML 已注入（%lu 字节）", (unsigned long)html.length];
}

- (NSString *)prepareHTML:(const char *)src port:(uint16_t)port size:(CGSize)size {
    NSString *html = [NSString stringWithUTF8String:src];
    html = [html stringByReplacingOccurrencesOfString:@"%%OVERLAY_WS_PORT%%"
                                          withString:[NSString stringWithFormat:@"%u", port]];
    html = [html stringByReplacingOccurrencesOfString:@"__W__"
                                          withString:[NSString stringWithFormat:@"%.0f", size.width]];
    html = [html stringByReplacingOccurrencesOfString:@"__H__"
                                          withString:[NSString stringWithFormat:@"%.0f", size.height]];
    return html;
}

#pragma mark - 安装

- (BOOL)installWithRemoteCall:(RemoteCall *)rc
                       wsPort:(uint16_t)wsPort
                     logBlock:(void (^)(NSString *))logBlock {
    _rc = rc;
    _log = [logBlock copy];
    if (!_rc) { [self log:@"RemoteCall 为空"]; return NO; }

    _win = [self findGameWindow];
    if (!_win) return NO;

    CGRect bounds = remote_getCGRect(_rc, _win, remote_sel(_rc, "bounds"));
    if (bounds.size.width < 1 || bounds.size.height < 1) {
        bounds = [[UIScreen mainScreen] bounds];
        [self log:@"窗口尺寸异常，回退到 UIScreen"];
    }
    _screenSize = bounds.size;
    [self log:@"游戏窗口 %.0f x %.0f", bounds.size.width, bounds.size.height];

    _webView = [self createWebView:bounds];
    if (!_webView) return NO;

    NSString *html = [self prepareHTML:kAceEspHTML port:wsPort size:bounds.size];
    [self loadHTML:html into:_webView];

    [self send:_win sel:"addSubview:" a0:_webView];
    [self send:_win sel:"bringSubviewToFront:" a0:_webView];

    _installed = YES;
    [self log:@"ESP overlay 安装完成"];
    return YES;
}

- (BOOL)attachAuxWebView:(RemoteCall *)rc role:(NSString *)role
                    html:(NSString *)html logBlock:(void (^)(NSString *))logBlock {
    if (!rc || !_win) return NO;
    _rc = rc;
    if (logBlock) _log = [logBlock copy];

    CGRect bounds = remote_getCGRect(_rc, _win, remote_sel(_rc, "bounds"));
    if (bounds.size.width < 1) bounds = [[UIScreen mainScreen] bounds];

    uint64_t wv = [self createWebView:bounds];
    if (!wv) return NO;

    [self loadHTML:html into:wv];
    [self send:_win sel:"addSubview:" a0:wv];
    [self send:_win sel:"bringSubviewToFront:" a0:wv];
    [self log:@"%@ overlay 挂载完成", role];
    return YES;
}

#pragma mark - 卸载

- (void)uninstall {
    if (!_rc || !_webView) return;
    [self send:_webView sel:"removeFromSuperview"];
    [self send:_webView sel:"stopLoading"];
    [self log:@"overlay 已移除"];
    _webView = 0;
    _installed = NO;
}

@end
