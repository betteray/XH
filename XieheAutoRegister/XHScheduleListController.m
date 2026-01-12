//
//  XHScheduleListController.m
//  XieheAutoRegister
//

#import "XHScheduleListController.h"

static void XHLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[XieheAutoReg] %@", message);
}

// 全局变量保存选中的排班字典
static NSDictionary *gSelectedScheduleDict = nil;

@implementation XHScheduleListController

#pragma mark - Class Methods

+ (NSString *)selectedScheduleFilePath {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    return [documentsDirectory stringByAppendingPathComponent:@"XieheSelectedSchedule.json"];
}

+ (void)saveSelectedScheduleDict:(NSDictionary *)scheduleDict {
    if (!scheduleDict) return;
    
    // 保存到全局变量
    gSelectedScheduleDict = [scheduleDict copy];
    
    // 保存到文件
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:scheduleDict 
                                                       options:NSJSONWritingPrettyPrinted 
                                                         error:&error];
    if (error) {
        XHLog(@"保存失败: 无法转换为JSON - %@", error);
        return;
    }
    
    NSString *filePath = [self selectedScheduleFilePath];
    [jsonData writeToFile:filePath atomically:YES];
    
    XHLog(@"排班数据已保存到: %@", filePath);
}

+ (NSDictionary *)currentSelectedScheduleDict {
    // 优先从全局变量获取
    if (gSelectedScheduleDict) {
        return gSelectedScheduleDict;
    }
    
    // 尝试从文件读取
    NSString *filePath = [self selectedScheduleFilePath];
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (data) {
        NSError *error = nil;
        NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data 
                                                             options:0 
                                                               error:&error];
        if (dict && !error) {
            gSelectedScheduleDict = dict;
            return dict;
        }
    }
    return nil;
}

+ (void)showWithScheduleData:(NSArray<NSDictionary *> *)amData
                      pmData:(NSArray<NSDictionary *> *)pmData
                    noonData:(NSArray<NSDictionary *> *)noonData
                  nowDateStr:(NSString *)dateStr {
    
    XHLog(@"[showWithScheduleData] 收到数据: 上午=%lu, 下午=%lu, 中午=%lu, 日期=%@",
          (unsigned long)amData.count,
          (unsigned long)pmData.count,
          (unsigned long)noonData.count,
          dateStr);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        XHScheduleListController *listVC = [[XHScheduleListController alloc] init];
        listVC.nowDateStr = dateStr;
        
        // 过滤有效排班
        listVC.amSchedules = [self filterValidSchedules:amData];
        listVC.pmSchedules = [self filterValidSchedules:pmData];
        listVC.noonSchedules = [self filterValidSchedules:noonData];
        
        XHLog(@"[showWithScheduleData] 过滤后: 上午=%lu, 下午=%lu, 中午=%lu",
              (unsigned long)listVC.amSchedules.count,
              (unsigned long)listVC.pmSchedules.count,
              (unsigned long)listVC.noonSchedules.count);
        
        UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:listVC];
        navController.modalPresentationStyle = UIModalPresentationFormSheet;
        
        // 获取当前最顶层的 ViewController
        UIWindow *keyWindow = nil;
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (window.isKeyWindow) {
                keyWindow = window;
                break;
            }
        }
        
        UIViewController *topVC = keyWindow.rootViewController;
        while (topVC.presentedViewController) {
            topVC = topVC.presentedViewController;
        }
        
        [topVC presentViewController:navController animated:YES completion:nil];
    });
}

/// 过滤有效排班（有医生名的）
+ (NSArray<NSDictionary *> *)filterValidSchedules:(NSArray<NSDictionary *> *)schedules {
    if (!schedules || ![schedules isKindOfClass:[NSArray class]]) {
        return @[];
    }
    
    NSMutableArray *validSchedules = [NSMutableArray array];
    for (NSDictionary *schedule in schedules) {
        if (![schedule isKindOfClass:[NSDictionary class]]) {
            continue;
        }
        
        // 检查是否有医生名
        id docName = schedule[@"docName"];
        if (docName && [docName isKindOfClass:[NSString class]] && [(NSString *)docName length] > 0) {
            [validSchedules addObject:schedule];
        }
    }
    
    XHLog(@"[filterValidSchedules] 原始 %lu 条 -> 过滤后 %lu 条",
          (unsigned long)schedules.count,
          (unsigned long)validSchedules.count);
    
    return [validSchedules copy];
}

#pragma mark - Lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.view.backgroundColor = [UIColor whiteColor];
    self.title = [NSString stringWithFormat:@"排班列表 - %@", self.nowDateStr ?: @""];
    
    // 添加关闭按钮
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"关闭" 
                                                                              style:UIBarButtonItemStyleDone 
                                                                             target:self 
                                                                             action:@selector(dismissSelf)];
    
    // 创建 TableView
    UITableView *tableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleGrouped];
    tableView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    tableView.dataSource = self;
    tableView.delegate = self;
    [tableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"ScheduleCell"];
    [self.view addSubview:tableView];
    self.tableView = tableView;
    
    XHLog(@"排班数据准备完成: 上午 %lu 条, 中午 %lu 条, 下午 %lu 条",
          (unsigned long)self.amSchedules.count,
          (unsigned long)self.noonSchedules.count,
          (unsigned long)self.pmSchedules.count);
}

- (void)dismissSelf {
    [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Helper Methods

- (NSArray<NSDictionary *> *)schedulesForSection:(NSInteger)section {
    switch (section) {
        case 0: return self.amSchedules ?: @[];
        case 1: return self.noonSchedules ?: @[];
        case 2: return self.pmSchedules ?: @[];
        default: return @[];
    }
}

- (NSString *)titleForSection:(NSInteger)section {
    switch (section) {
        case 0: return [NSString stringWithFormat:@"上午 (%lu)", (unsigned long)(self.amSchedules.count)];
        case 1: return [NSString stringWithFormat:@"中午 (%lu)", (unsigned long)(self.noonSchedules.count)];
        case 2: return [NSString stringWithFormat:@"下午 (%lu)", (unsigned long)(self.pmSchedules.count)];
        default: return @"";
    }
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 3; // 上午、中午、下午
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [self schedulesForSection:section].count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"ScheduleCell"];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    
    NSArray<NSDictionary *> *schedules = [self schedulesForSection:indexPath.section];
    if (indexPath.row < schedules.count) {
        NSDictionary *schedule = schedules[indexPath.row];
        
        // 主标题: 医生名 - 职称
        NSString *docName = schedule[@"docName"] ?: @"未知医生";
        NSString *titleShow = schedule[@"titleShow"] ?: @"";
        cell.textLabel.text = [NSString stringWithFormat:@"%@ - %@", docName, titleShow];
        cell.textLabel.font = [UIFont boldSystemFontOfSize:16];
        
        // 副标题: 日期 时间段 剩余号源
        NSString *accessSchTime = schedule[@"accessSchTime"] ?: @"";
        NSString *dayTypeString = schedule[@"dayTypeString"] ?: @"";
        id resNo = schedule[@"resNo"];
        NSString *remainStr = resNo ? [NSString stringWithFormat:@"剩余: %@", resNo] : @"无号源信息";
        NSString *goodAt = schedule[@"goodAt"] ?: @"";
        
        // 截取擅长的前30个字符
        if (goodAt.length > 30) {
            goodAt = [[goodAt substringToIndex:30] stringByAppendingString:@"..."];
        }
        
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ %@ %@", 
                                     accessSchTime, dayTypeString, remainStr];
        cell.detailTextLabel.font = [UIFont systemFontOfSize:13];
        cell.detailTextLabel.textColor = [UIColor grayColor];
        
        // 根据剩余号源设置颜色
        NSInteger remain = 0;
        if ([resNo isKindOfClass:[NSNumber class]]) {
            remain = [(NSNumber *)resNo integerValue];
        } else if ([resNo isKindOfClass:[NSString class]]) {
            remain = [(NSString *)resNo integerValue];
        }
        
        if (remain > 0) {
            cell.textLabel.textColor = [UIColor colorWithRed:0 green:0.6 blue:0 alpha:1.0]; // 绿色
        } else {
            cell.textLabel.textColor = [UIColor grayColor];
        }
        
        // 如果是当前选中的排班，显示选中标记
        NSDictionary *selected = gSelectedScheduleDict;
        if (selected) {
            NSString *currentDocId = schedule[@"docId"];
            NSString *selectedDocId = selected[@"docId"];
            NSString *currentDate = schedule[@"accessSchTime"];
            NSString *selectedDate = selected[@"accessSchTime"];
            
            if ([currentDocId isEqualToString:selectedDocId] && [currentDate isEqualToString:selectedDate]) {
                cell.accessoryType = UITableViewCellAccessoryCheckmark;
            }
        }
    }
    
    return cell;
}

#pragma mark - UITableViewDelegate

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return [self titleForSection:section];
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    NSArray<NSDictionary *> *schedules = [self schedulesForSection:indexPath.section];
    if (indexPath.row < schedules.count) {
        NSDictionary *schedule = schedules[indexPath.row];
        
        // 保存选中的排班
        [XHScheduleListController saveSelectedScheduleDict:schedule];
        
        // 显示选中信息
        NSString *docName = schedule[@"docName"] ?: @"未知";
        NSString *docId = schedule[@"docId"] ?: @"未知";
        NSString *accessSchTime = schedule[@"accessSchTime"] ?: @"";
        NSString *accessSchId = schedule[@"accessSchId"] ?: @"未知";
        NSString *dayTypeString = schedule[@"dayTypeString"] ?: @"";
        
        XHLog(@"✅ 已选中排班:");
        XHLog(@"   医生: %@", docName);
        XHLog(@"   docId: %@", docId);
        XHLog(@"   accessSchId: %@", accessSchId);
        XHLog(@"   日期: %@ %@", accessSchTime, dayTypeString);
        
        // 弹出提示
        NSString *message = [NSString stringWithFormat:@"医生: %@\ndocId: %@\n日期: %@ %@\naccessSchId: %@", 
                            docName, docId, accessSchTime, dayTypeString, accessSchId];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"已选中排班"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            // 刷新列表显示选中状态
            [self.tableView reloadData];
        }]];
        
        [self presentViewController:alert animated:YES completion:nil];
    }
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 60;
}

@end
