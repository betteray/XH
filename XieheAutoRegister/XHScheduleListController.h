//
//  XHScheduleListController.h
//  XieheAutoRegister
//
//  排班列表展示控制器
//

#import <UIKit/UIKit.h>

@class HsDeptSchModel;
@class HsSchedulModel;

@interface XHScheduleListController : UIViewController <UITableViewDataSource, UITableViewDelegate>

@property (nonatomic, strong) HsDeptSchModel *schModel;
@property (nonatomic, strong) UITableView *tableView;

/// 当前日期字符串
@property (nonatomic, copy) NSString *nowDateStr;

/// 上午排班数组 (NSDictionary数组)
@property (nonatomic, strong) NSArray<NSDictionary *> *amSchedules;
/// 下午排班数组 (NSDictionary数组)
@property (nonatomic, strong) NSArray<NSDictionary *> *pmSchedules;
/// 中午排班数组 (NSDictionary数组)
@property (nonatomic, strong) NSArray<NSDictionary *> *noonSchedules;

/// 保存选中的排班数据到沙盒 (字典格式)
+ (void)saveSelectedScheduleDict:(NSDictionary *)scheduleDict;

/// 获取已保存的排班数据路径
+ (NSString *)selectedScheduleFilePath;

/// 弹出控制器显示排班列表 (使用字典数据)
+ (void)showWithScheduleData:(NSArray<NSDictionary *> *)amData
                      pmData:(NSArray<NSDictionary *> *)pmData
                    noonData:(NSArray<NSDictionary *> *)noonData
                  nowDateStr:(NSString *)dateStr;

/// 获取当前选中的排班 (从沙盒文件)
+ (NSDictionary *)currentSelectedScheduleDict;

@end
