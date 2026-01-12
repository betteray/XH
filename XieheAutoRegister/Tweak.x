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

// ============== 类声明 ==============

@interface NSObject(YYAdditions)
-(id)tnld_modelToJSONString;
@end

@interface HsProxy : NSObject
+ (instancetype)instance;
- (NSURL *)api_baseURL;
- (NSString *)srcId;
@end

@interface BaseRequest : NSObject
- (instancetype)init;
- (NSString *)URLString;
- (void)setURLString:(NSString *)urlString;
- (void)setDataClass:(Class)dataClass;
- (void)startWithSuccessBlock:(void (^)(id request, int response, id data))success 
                 failureBlock:(void (^)(id error))failure;
- (void)startAsynchronously:(id)block;
@end

@interface HsUnifiedRegistrationCommitRequest : BaseRequest
// 属性 getter
- (id)schId;
- (id)patId;
- (id)hosPatCardNo;
- (id)hosPatCardType;
- (id)patName;
- (id)phoneNo;
- (id)cardNo;
- (id)signalId;
- (id)takeIndex;
- (id)expectTimeInterval;
- (id)takePassword;
- (id)createTime;
- (id)fb1;
- (id)language;
- (id)subjectId;
- (id)deptId;
- (id)nonce;
- (id)blackbox;

// 属性 setter
- (void)setSchId:(id)schId;
- (void)setPatId:(id)patId;
- (void)setHosPatCardNo:(id)hosPatCardNo;
- (void)setHosPatCardType:(id)hosPatCardType;
- (void)setPatName:(id)patName;
- (void)setPhoneNo:(id)phoneNo;
- (void)setCardNo:(id)cardNo;
- (void)setSignalId:(id)signalId;
- (void)setTakeIndex:(id)takeIndex;
- (void)setExpectTimeInterval:(id)expectTimeInterval;
- (void)setTakePassword:(id)takePassword;
- (void)setCreateTime:(id)createTime;
- (void)setFb1:(id)fb1;
- (void)setLanguage:(id)language;
- (void)setSubjectId:(id)subjectId;
- (void)setDeptId:(id)deptId;
- (void)setNonce:(id)nonce;
- (void)setBlackbox:(id)blackbox;
@end

@interface HsRegisterModel : NSObject
@end

// HsUnifiedRegistrationDeptSchListRequest 科室排班列表请求
@interface HsUnifiedRegistrationDeptSchListRequest : BaseRequest
- (id)docName;
- (id)sectId;
- (id)docId;
- (id)schDate;
- (id)schType;
- (id)deptId;
- (id)subjectId;
- (id)todaySch;
- (id)hosDistId;
- (id)language;
- (id)subjectName;
- (id)dayType;
- (id)mediLevel;
- (id)resNoType;
- (id)nonce;
- (id)blackbox;
@end

// HsUnifiedRegistrationDocSchListRequest 医生排班列表请求 (/20002/104)
@interface HsUnifiedRegistrationDocSchListRequest : BaseRequest
- (id)docName;
- (id)sectId;
- (id)docId;
- (id)schDate;
- (id)schType;
- (id)deptId;
- (id)subjectId;
- (id)todaySch;
- (id)hosDistId;
- (id)language;
@end

// 排班模型
@interface HsSchedulModel : NSObject
// 使用 valueForKey 读取，这里只声明必要的
@end

// 排班列表响应模型
@interface HsDeptSchModel : NSObject
- (id)nowDateStr;
- (id)daytype1Schs;   // 上午排班数组 (HsSchedulModel)
- (id)daytype2Schs;   // 下午排班数组 (HsSchedulModel)
- (id)daytype4Schs;   // 中午排班数组 (HsSchedulModel)
- (id)mediLevels;
@end

@interface HsXHPatientDetailModel : NSObject
- (id)patId;
- (id)patId32;
- (id)patName;
- (id)chnName;
- (id)cardNo;
- (id)cardNoType;
- (id)cardNoTypeDesc;
- (id)phoneNo;
- (id)documentId;
- (id)relation;
- (id)authStatus;
- (id)authStatusDesc;
- (id)accessPatId;
- (id)isDelete;
- (id)hasCanFaceAuth;
- (id)hasShowFaceAuthButton;
- (id)medInsCardNo;
@end

@interface HsXHPatientDetailViewController : UIViewController
- (HsXHPatientDetailModel *)detailModel;
- (void)setDetailModel:(HsXHPatientDetailModel *)model;
@end

@interface NSUserDefaults (DriverToken)
+ (NSString *)driverToken;
@end

// ============== 配置 ==============

// ============== 配置 ==============

// 触发时间配置
static NSInteger kTriggerHour = 22;            // 触发小时 (24小时制) - 15:00
static NSInteger kTriggerMinute = 45;           // 触发分钟


// ============== 全局变量 ==============

static PreciseGCDTimer *gDailyTimer = nil;
static HsXHPatientDetailModel *gHsXHPatientDetailModel = nil;  // 保存最后获取的患者信息

// ============== 工具函数 ==============

static void XHLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[XieheAutoReg] %@", message);
}

// ============== 核心功能 ==============

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

static void sendRegistrationRequest() {
    XHLog(@"开始发送挂号请求...");
    
    // 从配置文件读取患者数据
    NSDictionary *patientData = loadPatientDataFromFile();
    if (!patientData) {
        XHLog(@"错误: 未找到患者数据，请先在App中选择患者");
        return;
    }
    
    // 从配置文件读取排班数据
    NSDictionary *scheduleData = loadScheduleDataFromFile();
    if (!scheduleData) {
        XHLog(@"错误: 未找到排班数据，请先在App中选择排班");
        return;
    }
    
    // 提取患者信息
    NSString *patId = patientData[@"patId"];
    NSString *patName = patientData[@"patName"] ?: patientData[@"chnName"];
    NSString *cardNo = patientData[@"cardNo"];
    NSString *phoneNo = patientData[@"phoneNo"];
    
    // 提取排班信息
    NSString *schId = scheduleData[@"schId"];
    NSString *accessSchId = scheduleData[@"accessSchId"];
    NSString *subjectId = scheduleData[@"subjectId"];
    NSString *deptId = scheduleData[@"deptId"];
    NSString *docName = scheduleData[@"docName"];
    NSString *schDate = scheduleData[@"schDate"];
    
    // 验证必要参数
    if (!patId || !patName) {
        XHLog(@"错误: 患者信息不完整 (patId=%@, patName=%@)", patId, patName);
        return;
    }
    
    if (!schId || !subjectId || !deptId) {
        XHLog(@"错误: 排班信息不完整 (schId=%@, subjectId=%@, deptId=%@)", schId, subjectId, deptId);
        return;
    }
    
    XHLog(@"========== 准备发送挂号请求 ==========");
    XHLog(@"患者信息:");
    XHLog(@"  patId:    %@", patId);
    XHLog(@"  patName:  %@", patName);
    XHLog(@"  cardNo:   %@", cardNo);
    XHLog(@"  phoneNo:  %@", phoneNo);
    XHLog(@"排班信息:");
    XHLog(@"  schId:      %@", schId);
    XHLog(@"  accessSchId:%@", accessSchId);
    XHLog(@"  subjectId:  %@", subjectId);
    XHLog(@"  deptId:     %@", deptId);
    XHLog(@"  docName:    %@", docName);
    XHLog(@"  schDate:    %@", schDate);
    XHLog(@"===========================================");
    
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
    
    // 发送请求 - 使用空 block 避免崩溃
    [request startWithSuccessBlock:^(__unused id req, int response, __unused id data) {
        XHLog(@"✅ 挂号请求成功! response=%d", response);
        
    } failureBlock:^(__unused id error) {
        XHLog(@"❌ 挂号请求失败");
    }];
    
    XHLog(@"请求已发送，等待响应...");
}

// ============== Hook ==============

%hook AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    BOOL result = %orig;
    
    XHLog(@"App 启动，初始化自动挂号模块");

    // 或者方法2的使用
    PreciseGCDTimer *timer = [[PreciseGCDTimer alloc] init];
    timer.triggerBlock = ^{
        sendRegistrationRequest();
    };
    [timer startDailyAtHour:kTriggerHour minute:kTriggerMinute];
    
    // 保存timer引用
    gDailyTimer = timer;
    
    return result;
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
