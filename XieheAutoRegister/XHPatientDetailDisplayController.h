//
//  XHPatientDetailDisplayController.h
//  XieheAutoRegister
//

#import <UIKit/UIKit.h>

@class HsXHPatientDetailModel;

@interface XHPatientDetailDisplayController : UIViewController <UITableViewDataSource, UITableViewDelegate>

@property (nonatomic, strong) HsXHPatientDetailModel *patientModel;
@property (nonatomic, strong) NSDictionary *patientDict;
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) NSArray *dataKeys;
@property (nonatomic, strong) NSArray *dataValues;

/// 保存患者数据到沙盒 (Model-based)
+ (void)savePatientModel:(HsXHPatientDetailModel *)model;

/// 获取患者数据保存路径
+ (NSString *)patientDataFilePath;

/// 弹出控制器显示患者详情 (Model-based)
+ (void)showWithPatientModel:(HsXHPatientDetailModel *)model;

/// 保存患者数据到沙盒 (Dictionary-based, for NSURLSession interception)
+ (void)savePatientDict:(NSDictionary *)patientDict;

/// 弹出控制器显示患者详情 (Dictionary-based, for NSURLSession interception)
+ (void)showWithPatientDict:(NSDictionary *)patientDict;

@end
