//
//  AceOverlay.mm
//  跨进程 overlay 实现
//
//  流程：找游戏 UIWindow → 在目标进程里 alloc WKWebView
//        → initWithFrame: → loadHTMLString: → addSubview: → 推数据
//
#import "AceOverlay.h"
#import "AceOffsets.h"
#import "../kexploit/TaskRop/RemoteCall.h"

#import <objc/runtime.h>
#import <stdarg.h>

// ---------------------------------------------------------------------------
// 内嵌 HTML：横屏 Canvas 绘制。__W__ / __H__ 在运行时替换成真实窗口尺寸。
// ---------------------------------------------------------------------------
static const char *kAceHTML =
"<!DOCTYPE html><html><head>"
"<meta name='viewport' content='width=device-width,initial-scale=1,user-scalable=no'>"
"<style>"
"html,body{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:transparent;"
"-webkit-user-select:none;-webkit-touch-callout:none}"
"canvas{position:fixed;left:0;top:0;pointer-events:none}"
"</style></head><body><canvas id='c'></canvas><script>"
"var W=__W__,H=__H__;"
"var cv=document.getElementById('c'),ctx=cv.getContext('2d'),items=[];"
"var dpr=window.devicePixelRatio||1;"
"cv.width=W*dpr;cv.height=H*dpr;cv.style.width=W+'px';cv.style.height=H+'px';"
"ctx.setTransform(dpr,0,0,dpr,0,0);"
"function render(){"
"  ctx.clearRect(0,0,W,H);"
"  for(var i=0;i<items.length;i++){"
"    var e=items[i];"
"    if(e.visible===false)continue;"
"    if(e.w<=0||e.h<=0)continue;"
"    var x=e.x,y=e.y,w=e.w,h=e.h;"
"    ctx.strokeStyle=e.team?'#4ade80':'#ff4d4d';"
"    ctx.lineWidth=1.5;"
"    ctx.strokeRect(x,y,w,h);"
"    var pct=e.hpMax>0?Math.max(0,Math.min(1,e.hp/e.hpMax)):0;"
"    ctx.fillStyle='rgba(0,0,0,0.6)';"
"    ctx.fillRect(x,y-7,w,4);"
"    ctx.fillStyle=pct>0.5?'#4ade80':(pct>0.25?'#facc15':'#ef4444');"
"    ctx.fillRect(x,y-7,w*pct,4);"
"    ctx.font='12px -apple-system,Helvetica';"
"    ctx.textAlign='center';"
"    ctx.lineWidth=3;"
"    ctx.strokeStyle='rgba(0,0,0,0.85)';"
"    var label=(e.name||'')+'  '+(e.dist||0)+'m';"
"    ctx.strokeText(label,x+w/2,y-12);"
"    ctx.fillStyle=e.team?'#4ade80':'#ffffff';"
"    ctx.fillText(label,x+w/2,y-12);"
"  }"
"  requestAnimationFrame(render);"
"}"
"render();"
"window.aceUpdate=function(a){items=a||[];};"
"</script></body></html>";

// ---------------------------------------------------------------------------
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

/// initWithFrame:configuration: 这类「CGRect + 额外参数」的调用。
/// lara 的 remote_setCGRect 只支持纯 CGRect 参数，这里扩展一个。
- (void)msgWithRect:(uint64_t)obj sel:(const char *)name rect:(CGRect)rect extra:(uint64_t)extra {
    uint64_t where = _rc.trojanMem;
    [_rc remote_write:where from:&rect size:sizeof(rect)];

    // 借用 -[CAMetalDrawable dirtyRect] 的 ldp d0,d1,[x0,#0x20]; ldp d2,d3,[x0,#0x30]
    Class camd = NSClassFromString(@"CAMetalDrawable");
    Method m = class_getInstanceMethod(camd, @selector(dirtyRect));
    RemoteArbCall(_rc, method_getImplementation(m), where - 0x20);

    remote_msg(_rc, obj, remote_sel(_rc, name), extra, 0, 0, 0);
}

#pragma mark - 找游戏窗口

- (uint64_t)findGameWindow {
    uint64_t appCls = remote_getClass(_rc, "UIApplication");
    if (!appCls) { [self log:@"拿不到 UIApplication 类"]; return 0; }

    uint64_t app = [self send:appCls sel:"sharedApplication"];
    if (!app) { [self log:@"sharedApplication 为空"]; return 0; }

    // iOS 13+：connectedScenes → windows
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

            // 优先挑 hidden == NO 且非 WKWebView 的窗口
            uint64_t fallback = 0;
            for (uint64_t j = 0; j < nWins; j++) {
                uint64_t w = remote_msg(_rc, wins, remote_sel(_rc, "objectAtIndex:"), j, 0, 0, 0);
                if (!w) continue;
                if (!fallback) fallback = w;
                if ([self send:w sel:"isHidden"] == 0) {
                    [self log:@"找到可见窗口 @ 0x%llx (scene %llu, idx %llu)", w,
                          (unsigned long long)i, (unsigned long long)j];
                    return w;
                }
            }
            if (fallback) {
                [self log:@"没有可见窗口，用兜底 @ 0x%llx", fallback];
                return fallback;
            }
        }
    }

    // 老 API 兜底
    uint64_t kw = [self send:app sel:"keyWindow"];
    if (kw) { [self log:@"兜底 keyWindow @ 0x%llx", kw]; return kw; }

    [self log:@"没找到任何窗口"];
    return 0;
}

#pragma mark - 建 WKWebView

- (uint64_t)createWebView:(CGRect)frame {
    uint64_t wvCls = remote_getClass(_rc, "WKWebView");
    if (!wvCls) { [self log:@"WKWebView 类拿不到"]; return 0; }

    uint64_t wv = [self send:wvCls sel:"alloc"];
    if (!wv) { [self log:@"WKWebView alloc 失败"]; return 0; }

    // initWithFrame:  ← 只有一个 CGRect 参数，正好匹配 remote_setCGRect
    remote_setCGRect(_rc, wv, remote_sel(_rc, "initWithFrame:"), frame);
    if (!wv) { [self log:@"initWithFrame: 返回空"]; return 0; }

    // 透明 + 不吃触摸（HTML 里另有一层 pointer-events:none）
    [self send:wv sel:"setOpaque:" a0:0];
    [self send:wv sel:"setUserInteractionEnabled:" a0:0];
    [self send:wv sel:"setBackgroundColor:" a0:[self send:remote_getClass(_rc, "UIColor") sel:"clearColor"]];

    // scrollView 也需要处理，否则会有白底/回弹
    uint64_t sv = [self send:wv sel:"scrollView"];
    if (sv) {
        [self send:sv sel:"setScrollEnabled:" a0:0];
        [self send:sv sel:"setBackgroundColor:" a0:[self send:remote_getClass(_rc, "UIColor") sel:"clearColor"]];
        [self send:sv sel:"setUserInteractionEnabled:" a0:0];
    }

    [self log:@"WKWebView 创建完成 @ 0x%llx  frame=%.0fx%.0f", wv, frame.size.width, frame.size.height];
    return wv;
}

#pragma mark - 灌 HTML

- (void)loadHTML:(NSString *)html into:(uint64_t)wv {
    uint64_t rHTML = remote_NSString(_rc, html.UTF8String);
    uint64_t rBase = remote_NSString(_rc, "about:blank");
    if (!rHTML) { [self log:@"远程 HTML 字符串创建失败"]; return; }
    [self send:wv sel:"loadHTMLString:baseURL:" a0:rHTML a1:rBase];
    [self log:@"HTML 已注入（%lu 字节）", (unsigned long)html.length];
}

#pragma mark - 安装

- (BOOL)installWithRemoteCall:(RemoteCall *)rc logBlock:(void (^)(NSString *))logBlock {
    _rc = rc;
    _log = [logBlock copy];
    if (!_rc) { [self log:@"RemoteCall 为空"]; return NO; }

    _win = [self findGameWindow];
    if (!_win) return NO;

    CGRect bounds = remote_getCGRect(_rc, _win, remote_sel(_rc, "bounds"));
    if (bounds.size.width < 1 || bounds.size.height < 1) {
        [self log:@"窗口尺寸异常 (%.0fx%.0f)，改用屏幕尺寸",
              bounds.size.width, bounds.size.height];
        bounds = [[UIScreen mainScreen] bounds];
    }
    _screenSize = bounds.size;
    [self log:@"游戏窗口 %.0f x %.0f", bounds.size.width, bounds.size.height];

    // 替换 HTML 里的尺寸占位符
    NSString *html = [NSString stringWithUTF8String:kAceHTML];
    html = [html stringByReplacingOccurrencesOfString:@"__W__"
                                          withString:[NSString stringWithFormat:@"%.0f", bounds.size.width]];
    html = [html stringByReplacingOccurrencesOfString:@"__H__"
                                          withString:[NSString stringWithFormat:@"%.0f", bounds.size.height]];

    _webView = [self createWebView:bounds];
    if (!_webView) return NO;

    [self loadHTML:html into:_webView];

    // 挂到游戏窗口，置顶
    [self send:_win sel:"addSubview:" a0:_webView];
    [self send:_win sel:"bringSubviewToFront:" a0:_webView];

    _installed = YES;
    [self log:@"overlay 安装完成"];
    return YES;
}

#pragma mark - 推数据

- (void)pushEntities:(NSArray<NSDictionary *> *)entities {
    if (!_installed || !_webView || !_rc) return;

    NSData *json = [NSJSONSerialization dataWithJSONObject:entities ?: @[] options:0 error:nil];
    if (!json) return;

    NSString *js = [NSString stringWithFormat:@"window.aceUpdate(%@);",
                    [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]];

    uint64_t rjs = remote_NSString(_rc, js.UTF8String);
    if (!rjs) return;

    // completionHandler 传 0（nil block）
    [self send:_webView sel:"evaluateJavaScript:completionHandler:" a0:rjs a1:0];
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
