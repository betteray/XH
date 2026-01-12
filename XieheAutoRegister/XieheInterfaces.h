/**
 * 协和医院 App 类接口声明
 * 用于 Tweak 开发
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

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
