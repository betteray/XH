/**
 * 协和医院自动挂号 Tweak
 * 基于 HsUnifiedRegistrationCommitRequest 逆向分析
 * 
 * 功能: 在每天15:00自动触发挂号请求
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#import "PreciseGCDTimer.h"
#import "XHPatientDetailDisplayController.h"
#import "XHScheduleListController.h"
#import "XieheInterfaces.h"
#import "XieheSettings.h"
#import "XieheSettingsViewController.h"

// ============== 配置 ==============


// ============== 全局变量 ==============

static PreciseGCDTimer *gDailyTimer = nil;
static HsXHPatientDetailModel *gHsXHPatientDetailModel = nil;  // 保存最后获取的患者信息
static NSDictionary *gPatientData = nil;  // 预先读取的患者数据
static NSDictionary *gScheduleData = nil;  // 预先读取的排班数据
static BOOL gIsDataReady = NO;  // 数据是否已准备好

// ============== 工具函数 ==============

static void XHLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[XieheAutoReg] %@", message);
}

// 从沙盒读取患者数据
static NSDictionary* loadPatientDataFromFile() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:@"XiehePatientDetail.json"];
    
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) {
        XHLog(@"未找到患者数据文件");
        return nil;
    }
    
    NSError *error = nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error) {
        XHLog(@"解析患者数据失败: %@", error);
        return nil;
    }
    
    return dict;
}

// 从沙盒读取排班数据
static NSDictionary* loadScheduleDataFromFile() {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:@"XieheSelectedSchedule.json"];
    
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) {
        XHLog(@"未找到排班数据文件");
        return nil;
    }
    
    NSError *error = nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error) {
        XHLog(@"解析排班数据失败: %@", error);
        return nil;
    }
    
    return dict;
}

// 预先准备数据（仅读取文件和验证参数）
static void prepareRegistrationRequest() {
    // 从配置文件读取患者数据
    NSDictionary *patientData = loadPatientDataFromFile();
    if (!patientData) {
        XHLog(@"准备失败: 未找到患者数据");
        gIsDataReady = NO;
        return;
    }
    
    // 从配置文件读取排班数据
    NSDictionary *scheduleData = loadScheduleDataFromFile();
    if (!scheduleData) {
        XHLog(@"准备失败: 未找到排班数据");
        gIsDataReady = NO;
        return;
    }
    
    // 验证必要参数
    NSString *patId = patientData[@"patId"];
    NSString *patName = patientData[@"patName"] ?: patientData[@"chnName"];
    NSString *schId = scheduleData[@"schId"];
    NSString *subjectId = scheduleData[@"subjectId"];
    NSString *deptId = scheduleData[@"deptId"];
    
    if (!patId || !patName) {
        XHLog(@"准备失败: 患者信息不完整");
        gIsDataReady = NO;
        return;
    }
    
    if (!schId || !subjectId || !deptId) {
        XHLog(@"准备失败: 排班信息不完整");
        gIsDataReady = NO;
        return;
    }
    
    // 保存准备好的数据
    gPatientData = [patientData copy];
    gScheduleData = [scheduleData copy];
    gIsDataReady = YES;
    
    XHLog(@"✅ 数据已准备完成 - patId:%@, schId:%@", patId, schId);
}

static void sendRegistrationRequest() {
    XHLog(@"发送挂号请求...");
    
    // 检查数据是否已准备好
    if (!gIsDataReady || !gPatientData || !gScheduleData) {
        XHLog(@"❌ 错误: 数据未准备好，请先选择患者和排班");
        return;
    }
    
    // 提取患者信息
    NSString *patId = gPatientData[@"patId"];
    NSString *patName = gPatientData[@"patName"] ?: gPatientData[@"chnName"];
    NSString *cardNo = gPatientData[@"cardNo"];
    NSString *phoneNo = gPatientData[@"phoneNo"];
    
    // 提取排班信息
    NSString *schId = gScheduleData[@"schId"];
    NSString *subjectId = gScheduleData[@"subjectId"];
    NSString *deptId = gScheduleData[@"deptId"];
    
    // 创建请求对象
    HsUnifiedRegistrationCommitRequest *request = [[%c(HsUnifiedRegistrationCommitRequest) alloc] init];
    
    if (!request) {
        XHLog(@"错误: 创建请求对象失败");
        return;
    }
    
    // 设置请求参数
    [request setSchId:schId];
    [request setPatId:patId];
    [request setPatName:patName];
    [request setCardNo:cardNo];
    [request setPhoneNo:phoneNo];
    [request setSubjectId:subjectId];
    [request setDeptId:deptId];
    
    XHLog(@"========== 发送挂号请求 ==========");
    XHLog(@"schId:      %@", schId);
    XHLog(@"patId:      %@", patId);
    XHLog(@"patName:    %@", patName);
    XHLog(@"subjectId:  %@", subjectId);
    XHLog(@"deptId:     %@", deptId);
    XHLog(@"===================================");
    
    // 发送请求
    [request startWithSuccessBlock:^(int req, int response, id data) {
        XHLog(@"✅ 挂号请求成功! response=%d", response);
        
    } failureBlock:^(int error) {
        XHLog(@"❌ 挂号请求失败");
    }];
    
    XHLog(@"请求已发送，等待响应...");
}

// ============== Hook ==============

%hook AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    BOOL result = %orig;
    
    XHLog(@"App 启动，初始化自动挂号模块");

    // 创建并启动每日触发定时器（使用设置中的时间）
    PreciseGCDTimer *timer = [[PreciseGCDTimer alloc] init];
    timer.triggerBlock = ^{
        sendRegistrationRequest();
    };
    [timer startDailyAtHour:XieheGetTriggerHour() minute:XieheGetTriggerMinute()];
    
    // 保存timer引用
    gDailyTimer = timer;

    // 监听设置变更，更新定时器
    [[NSNotificationCenter defaultCenter] addObserverForName:XieheTriggerTimeChangedNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *note) {
        if (gDailyTimer) {
            [gDailyTimer stop];
            gDailyTimer = nil;
        }
        PreciseGCDTimer *newTimer = [[PreciseGCDTimer alloc] init];
        newTimer.triggerBlock = ^{
            sendRegistrationRequest();
        };
        [newTimer startDailyAtHour:XieheGetTriggerHour() minute:XieheGetTriggerMinute()];
        gDailyTimer = newTimer;
    }];
    
    return result;
}

%end

%hook UIViewController

- (void)motionEnded:(UIEventSubtype)motion withEvent:(UIEvent *)event {
    %orig;
    if (motion == UIEventSubtypeMotionShake) {
        dispatch_async(dispatch_get_main_queue(), ^{
            UIWindow *targetWindow = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindow *w in [UIApplication sharedApplication].windows) {
                    if (w.isKeyWindow) { targetWindow = w; break; }
                }
            } else {
                _Pragma("clang diagnostic push")
                _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
                targetWindow = UIApplication.sharedApplication.keyWindow;
                _Pragma("clang diagnostic pop")
            }
            UIViewController *root = targetWindow.rootViewController ?: UIApplication.sharedApplication.delegate.window.rootViewController;
            XieheSettingsViewController *vc = [[%c(XieheSettingsViewController) alloc] init];
            UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
            [root presentViewController:nav animated:YES completion:nil];
        });
    }
}

%end

// 钩取排班保存操作，在保存后准备请求
%hook XHScheduleListController

+ (void)saveSelectedScheduleDict:(NSDictionary *)scheduleDict {
    %orig;
    
    // 排班保存后，尝试准备请求
    XHLog(@"[Hook] 排班已保存，准备挂号请求");
    prepareRegistrationRequest();
}

%end

%hook BaseRequest

- (void)startWithSuccessBlock:(id)success failureBlock:(id)failure {
    // XHLog(@"[Hook] %@ startWithSuccessBlock", [self tnld_modelToJSONString]);
    
    // 如果是 HsUnifiedRegistrationCommitRequest，打印所有属性
    if ([self isKindOfClass:%c(HsUnifiedRegistrationCommitRequest)]) {
        HsUnifiedRegistrationCommitRequest *req = (HsUnifiedRegistrationCommitRequest *)self;
        XHLog(@"========== HsUnifiedRegistrationCommitRequest ==========");
        XHLog(@"schId:              %@", [req schId]);
        XHLog(@"patId:              %@", [req patId]);
        XHLog(@"hosPatCardNo:       %@", [req hosPatCardNo]);
        XHLog(@"hosPatCardType:     %@", [req hosPatCardType]);
        XHLog(@"patName:            %@", [req patName]);
        XHLog(@"phoneNo:            %@", [req phoneNo]);
        XHLog(@"cardNo:             %@", [req cardNo]);
        XHLog(@"signalId:           %@", [req signalId]);
        XHLog(@"takeIndex:          %@", [req takeIndex]);
        XHLog(@"expectTimeInterval: %@", [req expectTimeInterval]);
        XHLog(@"takePassword:       %@", [req takePassword]);
        XHLog(@"createTime:         %@", [req createTime]);
        XHLog(@"fb1:                %@", [req fb1]);
        XHLog(@"language:           %@", [req language]);
        XHLog(@"subjectId:          %@", [req subjectId]);
        XHLog(@"deptId:             %@", [req deptId]);
        XHLog(@"nonce:              %@", [req nonce]);
        XHLog(@"blackbox:           %@", [req blackbox]);
        XHLog(@"=========================================================");
    }
    
    %orig;
}

%end


// ============== NSURLSession 拦截 ==============
// 处理 /20002/104 响应数据
// 实际响应结构: { result: true, data: [ { schId, accessSchId, dayType, docName, subjectId, ... }, ... ] }
static void processDocSchListResponse(NSDictionary *responseDict, NSString *urlString) {
    if (!responseDict) return;
    
    // 检查 result 字段
    id resultValue = responseDict[@"result"];
    BOOL success = [resultValue boolValue];
    if (!success) {
        XHLog(@"[响应] 请求失败, result=%@", resultValue);
        return;
    }
    
    // 获取 data 数组
    id dataObj = responseDict[@"data"];
    if (![dataObj isKindOfClass:[NSArray class]]) {
        XHLog(@"[响应] data 字段不是数组, 类型: %@", [dataObj class]);
        return;
    }
    
    NSArray *dataArray = (NSArray *)dataObj;
    XHLog(@"[响应] 获取到 %lu 条排班数据", (unsigned long)[dataArray count]);
    
    // 分类排班数据
    NSMutableArray *amData = [NSMutableArray array];   // 上午 dayType=1
    NSMutableArray *pmData = [NSMutableArray array];   // 下午 dayType=2
    NSMutableArray *noonData = [NSMutableArray array]; // 中午/其他
    NSString *nowDateStr = nil;
    
    for (id item in dataArray) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        
        NSDictionary *sch = (NSDictionary *)item;
        
        // 获取日期 (取第一个有效的 schDate)
        if (!nowDateStr && sch[@"schDate"]) {
            nowDateStr = sch[@"schDate"];
        }
        
        // 按 dayType 分类
        NSString *dayType = [sch[@"dayType"] description];
        
        if ([dayType isEqualToString:@"1"]) {
            [amData addObject:sch];
        } else if ([dayType isEqualToString:@"2"]) {
            [pmData addObject:sch];
        } else {
            [noonData addObject:sch];
        }
    }
    
    XHLog(@"[响应] 分类完成 - 上午:%lu, 下午:%lu, 其他:%lu, 日期:%@",
          (unsigned long)[amData count], (unsigned long)[pmData count], 
          (unsigned long)[noonData count], nowDateStr);
    
    // 显示排班选择列表
    if ([amData count] + [pmData count] + [noonData count] > 0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [XHScheduleListController showWithScheduleData:amData
                                                    pmData:pmData
                                                  noonData:noonData
                                                nowDateStr:nowDateStr ?: @""];
        });
    }
}

// 处理 /20004/110 患者详情响应数据
// 实际响应结构: { result: true, data: { patId, patName, cardNo, phoneNo, ... } }
static void processPatientDetailResponse(NSDictionary *responseDict, NSString *urlString) {
    if (!responseDict) return;
    
    // 检查 result 字段
    id resultValue = responseDict[@"result"];
    BOOL success = [resultValue boolValue];
    if (!success) {
        XHLog(@"[患者详情] 请求失败, result=%@", resultValue);
        return;
    }
    
    // 获取 data 字典
    id dataObj = responseDict[@"data"];
    if (![dataObj isKindOfClass:[NSDictionary class]]) {
        XHLog(@"[患者详情] data 字段不是字典, 类型: %@", [dataObj class]);
        return;
    }
    
    NSDictionary *patientData = (NSDictionary *)dataObj;
    
    // 提取患者信息
    NSString *patId = [patientData[@"patId"] description];
    NSString *patName = patientData[@"patName"] ?: @"";
    NSString *cardNo = patientData[@"cardNo"] ?: @"";
    NSString *phoneNo = patientData[@"phoneNo"] ?: @"";
    
    XHLog(@"[患者详情] patId=%@, patName=%@, cardNo=%@, phoneNo=%@", 
          patId, patName, cardNo, phoneNo);
    
    // 保存患者数据到文件
    dispatch_async(dispatch_get_main_queue(), ^{
        [XHPatientDetailDisplayController savePatientDict:patientData];
        
        // 显示患者详情弹窗
        [XHPatientDetailDisplayController showWithPatientDict:patientData];
        
        // 患者数据保存后，尝试准备请求
        prepareRegistrationRequest();
    });
}


// Hook AFURLSessionManager (AFNetworking) 的 dataTask 创建
%hook AFURLSessionManager

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                               uploadProgress:(id)uploadProgressBlock
                             downloadProgress:(id)downloadProgressBlock
                            completionHandler:(void (^)(NSURLResponse *response, id responseObject, NSError *error))completionHandler {
    
    NSString *urlString = [[request URL] absoluteString];
    
    // 检查是否是 /20002/104 排班请求 或 /20004/110 患者详情请求
    BOOL isDocSchRequest = urlString && [urlString containsString:@"/20002/104"];
    BOOL isPatientDetailRequest = urlString && [urlString containsString:@"/20004/110"];
    
    if (isDocSchRequest || isPatientDetailRequest) {
        XHLog(@"[AFNetworking] 拦截请求: %@", urlString);
        
        // 包装 completionHandler
        void (^wrappedHandler)(NSURLResponse *, id, NSError *) = ^(NSURLResponse *response, id responseObject, NSError *error) {
            if (responseObject && !error) {
                XHLog(@"[AFNetworking] 响应到达, 类型: %@", [responseObject class]);
                
                NSDictionary *responseDict = nil;
                
                // responseObject 可能是 NSDictionary 或 NSData
                if ([responseObject isKindOfClass:[NSDictionary class]]) {
                    responseDict = (NSDictionary *)responseObject;
                } else if ([responseObject isKindOfClass:[NSData class]]) {
                    // 解析 JSON
                    NSError *jsonError = nil;
                    id json = [NSJSONSerialization JSONObjectWithData:(NSData *)responseObject options:0 error:&jsonError];
                    if (!jsonError && [json isKindOfClass:[NSDictionary class]]) {
                        responseDict = (NSDictionary *)json;
                    }
                }
                
                if (responseDict) {
                    if (isDocSchRequest) {
                        processDocSchListResponse(responseDict, urlString);
                    } else if (isPatientDetailRequest) {
                        processPatientDetailResponse(responseDict, urlString);
                    }
                }
            }
            
            // 调用原始 handler
            if (completionHandler) {
                completionHandler(response, responseObject, error);
            }
        };
        
        return %orig(request, uploadProgressBlock, downloadProgressBlock, wrappedHandler);
    }
    
    return %orig;
}

%end

%ctor {
    @autoreleasepool {
        XHLog(@"Tweak 加载完成");
    }
}
