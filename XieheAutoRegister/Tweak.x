/**
 * 协和医院自动挂号 Tweak
 * 基于 HsUnifiedRegistrationCommitRequest 逆向分析
 * 
 * 功能: 在每天15:00自动触发挂号请求
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "PreciseGCDTimer.h"

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

// 挂号配置 - 请根据实际情况修改
static NSString *kTargetHosPatCardNo = @"";    // 就诊卡号
static NSString *kTargetHosPatCardType = @"";  // 卡类型

static NSString *kTargetSubjectId = @"6f13cc99898e415a9af5e8f29bad4e4b";       // 科室ID
static NSString *kTargetDeptId = @"3725ea598f9e456f8040ecf280a5de8c";          // 部门ID
static NSString *kTargetSchId = @"4250b6dc15cf4a6fa353387810f45603";           // 排班ID - 需要动态获取

// 触发时间配置
static NSInteger kTriggerHour = 23;            // 触发小时 (24小时制)
static NSInteger kTriggerMinute = 0;           // 触发分钟
//static NSInteger kTriggerSecond = 0;           // 触发秒


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

static void sendRegistrationRequest() {
    XHLog(@"开始发送挂号请求...");
    
    // 检查必要参数
    if (!gHsXHPatientDetailModel) {
        XHLog(@"错误: 患者信息未配置");
        return;
    }
    
    // 创建请求对象
    HsUnifiedRegistrationCommitRequest *request = [[%c(HsUnifiedRegistrationCommitRequest) alloc] init];
    
    if (!request) {
        XHLog(@"错误: 创建请求对象失败");
        return;
    }
    
    // 设置请求参数
    [request setSchId:kTargetSchId];
    [request setPatId:[gHsXHPatientDetailModel patId]];
    [request setPatName:[gHsXHPatientDetailModel patName]];
    [request setCardNo:[gHsXHPatientDetailModel cardNo]];
    [request setPhoneNo:[gHsXHPatientDetailModel phoneNo]];
    [request setSubjectId:kTargetSubjectId];
    [request setDeptId:kTargetDeptId];

    // [request setLanguage:@"zh"];
    // [request setHosPatCardNo:kTargetHosPatCardNo];
    // [request setHosPatCardType:kTargetHosPatCardType];
    // [request setCreateTime:getCurrentTimestamp()];
    // 
    // // signalId, takeIndex, expectTimeInterval, takePassword, fb1 可能需要根据实际情况设置
    // [request setSignalId:@""];
    // [request setTakeIndex:@""];
    // [request setExpectTimeInterval:@""];
    // [request setTakePassword:@""];
    // [request setFb1:@""];
    
    XHLog(@"请求参数已设置:");
    XHLog(@"  schId: %@", kTargetSchId);
    XHLog(@"  patId: %@", [gHsXHPatientDetailModel patId]);
    XHLog(@"  patName: %@", [gHsXHPatientDetailModel patName]);
    XHLog(@"  subjectId: %@", kTargetSubjectId);
    XHLog(@"  deptId: %@", kTargetDeptId);
    
    // 发送请求
    [request startWithSuccessBlock:^(id req, int response, id data) {
        XHLog(@"✅ 挂号请求成功!");
        XHLog(@"响应数据: %@ - %@", req, data);
        
    } failureBlock:^(id req) {
        XHLog(@"挂号请求失败: %@", req);
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


%hook HsXHPatientDetailViewController

- (void)setDetailModel:(HsXHPatientDetailModel *)model {
    %orig;
    
    XHLog(@"setDetailModel: model is %@", [model tnld_modelToJSONString]);
    
    if (!model) {
        return;
    }

   gHsXHPatientDetailModel = model;
}

%end

%ctor {
    @autoreleasepool {
        XHLog(@"Tweak 加载完成");
    }
}
