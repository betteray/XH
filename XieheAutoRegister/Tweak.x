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

// 保存医生排班数据副本
static NSMutableArray *gDocSchedulesCopy = nil;
static NSMutableArray *gPendingScheduleModels = nil;  // 待处理的排班模型
static NSString *gNowDateStr = nil;
static BOOL gIsDocSchListRequestPending = NO;  // 是否有 /20002/104 请求待处理
static NSString *gPendingSubjectId = nil;  // 当前请求的 subjectId
static NSString *gPendingSubjectName = nil;  // 当前请求的 subjectName

// 从排班模型中提取数据为字典 (使用 runtime 读取 ivar)
static NSDictionary* extractScheduleData(id schedule) {
    if (!schedule) return nil;
    
    NSMutableDictionary *data = [NSMutableDictionary dictionary];
    
    // 使用 runtime 获取类的所有 ivar（实例变量）
    Class cls = [schedule class];
    while (cls && cls != [NSObject class]) {
        unsigned int ivarCount = 0;
        Ivar *ivars = class_copyIvarList(cls, &ivarCount);
        
        for (unsigned int i = 0; i < ivarCount; i++) {
            const char *ivarName = ivar_getName(ivars[i]);
            if (!ivarName) continue;
            
            NSString *key = [NSString stringWithUTF8String:ivarName];
            // 移除下划线前缀
            if ([key hasPrefix:@"_"]) {
                key = [key substringFromIndex:1];
            }
            
            @try {
                id value = object_getIvar(schedule, ivars[i]);
                if (value && value != [NSNull null]) {
                    // 只保存 JSON 兼容的类型
                    if ([value isKindOfClass:[NSString class]] || 
                        [value isKindOfClass:[NSNumber class]]) {
                        data[key] = value;
                    } else if ([value isKindOfClass:[NSArray class]] || 
                               [value isKindOfClass:[NSDictionary class]]) {
                        if ([NSJSONSerialization isValidJSONObject:value]) {
                            data[key] = value;
                        } else {
                            data[key] = [value description];
                        }
                    } else {
                        data[key] = [value description];
                    }
                }
            } @catch (NSException *e) {
                // 忽略不存在的属性
            }
        }
        
        if (ivars) {
            free(ivars);
        }
        
        // 遍历父类
        cls = class_getSuperclass(cls);
    }
    
    return data;
}

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

// Hook startAsynchronously: 拦截响应数据
- (void)startAsynchronously:(id)callback {
    NSString *urlString = [self URLString];
    
    // 检查是否是医生排班请求 /20002/104
    if (urlString && [urlString containsString:@"/20002/104"]) {
        XHLog(@"========== 拦截医生排班请求 /20002/104 ==========");
        XHLog(@"URLString: %@", urlString);
        
        // 设置待处理标志，准备收集 HsSchedulModel 数据
        gIsDocSchListRequestPending = YES;
        gPendingScheduleModels = [NSMutableArray array];
        
        // 延迟处理收集到的数据（等待所有模型解析完成）
        // 捕获数组副本，避免在 block 执行时全局变量已被修改
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // 获取并复制当前收集的数据
            NSArray *collectedData = gPendingScheduleModels ? [gPendingScheduleModels copy] : @[];
            
            XHLog(@"[延迟处理] 收集到 %lu 个排班数据", (unsigned long)[collectedData count]);
            
            // 重置状态（先重置，避免后续请求干扰）
            gIsDocSchListRequestPending = NO;
            gPendingScheduleModels = nil;
            
            if ([collectedData count] > 0) {
                // 分类排班数据
                NSMutableArray *amData = [NSMutableArray array];
                NSMutableArray *pmData = [NSMutableArray array];
                NSMutableArray *noonData = [NSMutableArray array];
                NSString *nowDateStr = nil;
                
                for (id item in collectedData) {
                    if (![item isKindOfClass:[NSDictionary class]]) {
                        XHLog(@"[警告] 数据类型不是字典: %@", [item class]);
                        continue;
                    }
                    NSDictionary *data = (NSDictionary *)item;
                    
                    XHLog(@"[处理] schId=%@, accessSchId=%@, docName=%@, dayType=%@",
                          data[@"schId"], data[@"accessSchId"], data[@"docName"], data[@"dayType"]);
                    
                    // 获取日期
                    if (!nowDateStr && data[@"schDate"]) {
                        id schDate = data[@"schDate"];
                        if ([schDate isKindOfClass:[NSString class]]) {
                            nowDateStr = schDate;
                        } else {
                            nowDateStr = [schDate description];
                        }
                    }
                    
                    // 按时段分类 (dayType 可能是 NSString 或 NSNumber)
                    id dayTypeValue = data[@"dayType"];
                    NSString *dayType = nil;
                    if ([dayTypeValue isKindOfClass:[NSString class]]) {
                        dayType = dayTypeValue;
                    } else if ([dayTypeValue isKindOfClass:[NSNumber class]]) {
                        dayType = [dayTypeValue stringValue];
                    }
                    
                    if ([dayType isEqualToString:@"1"]) {
                        [amData addObject:data];
                    } else if ([dayType isEqualToString:@"2"]) {
                        [pmData addObject:data];
                    } else {
                        [noonData addObject:data];
                    }
                }
                
                XHLog(@"[分类完成] 上午:%lu, 下午:%lu, 其他:%lu", 
                      (unsigned long)[amData count], (unsigned long)[pmData count], (unsigned long)[noonData count]);
                
                // 显示排班选择列表
                if ([amData count] + [pmData count] + [noonData count] > 0) {
                    [XHScheduleListController showWithScheduleData:amData 
                                                            pmData:pmData 
                                                          noonData:noonData 
                                                        nowDateStr:nowDateStr ?: @""];
                }
            }
        });
    }
    
    // 检查是否是科室排班列表请求
    if ([self isKindOfClass:%c(HsUnifiedRegistrationDeptSchListRequest)]) {
        HsUnifiedRegistrationDeptSchListRequest *req = (HsUnifiedRegistrationDeptSchListRequest *)self;
        XHLog(@"========== HsUnifiedRegistrationDeptSchListRequest 请求 ==========");
        XHLog(@"deptId:      %@", [req deptId]);
        XHLog(@"subjectId:   %@", [req subjectId]);
        XHLog(@"subjectName: %@", [req subjectName]);
        XHLog(@"schDate:     %@", [req schDate]);
        XHLog(@"dayType:     %@", [req dayType]);
        XHLog(@"docId:       %@", [req docId]);
        XHLog(@"docName:     %@", [req docName]);
        XHLog(@"================================================================");
        
        // 保存 subjectId 和 subjectName，供后续 /20002/104 请求使用
        if ([req subjectId]) {
            gPendingSubjectId = [[req subjectId] copy];
        }
        if ([req subjectName]) {
            gPendingSubjectName = [[req subjectName] copy];
        }
    }
    
    %orig;
}

%end


// Hook HsSchedulModel 来拦截医生排班数据的设置
// 当 /20002/104 响应解析时，会创建 HsSchedulModel 对象并设置其属性
%hook HsSchedulModel

- (void)setSchId:(id)schId {
    %orig;
    if (schId) {
        XHLog(@"[HsSchedulModel] setSchId: %@", schId);
    }
}

- (void)setAccessSchId:(id)accessSchId {
    %orig;
    if (accessSchId) {
        XHLog(@"[HsSchedulModel] setAccessSchId: %@", accessSchId);
    }
}

// 在 setDocName: 时提取数据，此时所有关键属性应该都已设置
- (void)setDocName:(id)docName {
    %orig;
    if (docName) {
        XHLog(@"[HsSchedulModel] setDocName: %@", docName);
        
        // 当 docName 设置时，提取完整数据
        if (gIsDocSchListRequestPending) {
            if (!gPendingScheduleModels) {
                gPendingScheduleModels = [NSMutableArray array];
            }
            
            // 立即提取数据
            NSDictionary *extractedData = extractScheduleData(self);
            if (extractedData && extractedData[@"schId"] && extractedData[@"accessSchId"] && extractedData[@"docName"]) {
                // 添加 subjectId 和 subjectName（从之前的 DeptSchListRequest 保存的）
                NSMutableDictionary *data = [extractedData mutableCopy];
                if (gPendingSubjectId && !data[@"subjectId"]) {
                    data[@"subjectId"] = gPendingSubjectId;
                }
                if (gPendingSubjectName && !data[@"subjectName"]) {
                    data[@"subjectName"] = gPendingSubjectName;
                }
                
                XHLog(@"[HsSchedulModel] 提取完整数据: schId=%@, accessSchId=%@, docName=%@, dayType=%@, subjectId=%@", 
                      data[@"schId"], data[@"accessSchId"], data[@"docName"], data[@"dayType"], data[@"subjectId"]);
                [gPendingScheduleModels addObject:data];
            }
        }
    }
}

%end


%hook HsXHPatientDetailViewController

- (void)setDetailModel:(HsXHPatientDetailModel *)model {
    %orig;
    
    XHLog(@"setDetailModel: model is %@", [model tnld_modelToJSONString]);
    
    if (!model) {
        return;
    }

    gHsXHPatientDetailModel = model;
    
    // 保存到沙盒
    [XHPatientDetailDisplayController savePatientModel:model];
    
    // 弹出控制器显示详情
    [XHPatientDetailDisplayController showWithPatientModel:model];
}

%end

%ctor {
    @autoreleasepool {
        XHLog(@"Tweak 加载完成");
    }
}
