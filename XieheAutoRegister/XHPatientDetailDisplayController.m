//
//  XHPatientDetailDisplayController.m
//  XieheAutoRegister
//

#import "XHPatientDetailDisplayController.h"

static void XHLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[XieheAutoReg] %@", message);
}

@interface NSObject(YYAdditions)
-(id)tnld_modelToJSONString;
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

@implementation XHPatientDetailDisplayController

#pragma mark - Class Methods

+ (NSString *)patientDataFilePath {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths firstObject];
    return [documentsDirectory stringByAppendingPathComponent:@"XiehePatientDetail.json"];
}

+ (void)savePatientModel:(HsXHPatientDetailModel *)model {
    if (!model) return;
    
    NSString *jsonString = [model tnld_modelToJSONString];
    if (!jsonString) {
        XHLog(@"保存失败: 无法转换为JSON");
        return;
    }
    
    NSString *filePath = [self patientDataFilePath];
    NSError *error = nil;
    [jsonString writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    
    if (error) {
        XHLog(@"保存患者数据失败: %@", error);
    } else {
        XHLog(@"患者数据已保存到: %@", filePath);
    }
}

+ (void)showWithPatientModel:(HsXHPatientDetailModel *)model {
    dispatch_async(dispatch_get_main_queue(), ^{
        XHPatientDetailDisplayController *detailVC = [[XHPatientDetailDisplayController alloc] init];
        detailVC.patientModel = model;
        
        UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:detailVC];
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

#pragma mark - Dictionary-based Methods

+ (void)savePatientDict:(NSDictionary *)patientDict {
    if (!patientDict) return;
    
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:patientDict options:NSJSONWritingPrettyPrinted error:&error];
    if (error) {
        XHLog(@"保存失败: 无法序列化为JSON: %@", error);
        return;
    }
    
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *filePath = [self patientDataFilePath];
    [jsonString writeToFile:filePath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    
    if (error) {
        XHLog(@"保存患者数据失败: %@", error);
    } else {
        XHLog(@"患者数据已保存到: %@", filePath);
    }
}

+ (void)showWithPatientDict:(NSDictionary *)patientDict {
    dispatch_async(dispatch_get_main_queue(), ^{
        XHPatientDetailDisplayController *detailVC = [[XHPatientDetailDisplayController alloc] init];
        detailVC.patientDict = patientDict;
        
        UINavigationController *navController = [[UINavigationController alloc] initWithRootViewController:detailVC];
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

#pragma mark - Lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.view.backgroundColor = [UIColor whiteColor];
    self.title = @"患者详情";
    
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
    [tableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"Cell"];
    [self.view addSubview:tableView];
    self.tableView = tableView;
    
    // 准备数据
    [self prepareData];
}

- (void)prepareData {
    // Support both model-based and dict-based data
    if (self.patientDict) {
        [self prepareDataFromDict];
    } else if (self.patientModel) {
        [self prepareDataFromModel];
    }
}

- (void)prepareDataFromDict {
    NSDictionary *dict = self.patientDict;
    if (!dict) return;
    
    // 定义要显示的字段 - 只显示基本信息和用于发送请求的关键字段
    NSArray *keys = @[@"patId", @"patName", @"phoneNo", @"cardNo"];
    
    NSMutableArray *values = [NSMutableArray array];
    for (NSString *key in keys) {
        id value = dict[key];
        if (value && value != [NSNull null]) {
            [values addObject:[NSString stringWithFormat:@"%@", value]];
        } else {
            [values addObject:@"(null)"];
        }
    }
    
    self.dataKeys = keys;
    self.dataValues = [values copy];
}

- (void)prepareDataFromModel {
    HsXHPatientDetailModel *model = self.patientModel;
    if (!model) return;
    
    // 只显示基本信息和用于发送请求的关键字段
    self.dataKeys = @[@"patId", @"patName", @"phoneNo", @"cardNo"];
    
    self.dataValues = @[
        [model patId] ?: @"(null)",
        [model patName] ?: @"(null)",
        [model phoneNo] ?: @"(null)",
        [model cardNo] ?: @"(null)"
    ];
}

- (void)dismissSelf {
    [self dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.dataKeys.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"Cell" forIndexPath:indexPath];
    cell.textLabel.numberOfLines = 0;
    cell.textLabel.font = [UIFont systemFontOfSize:14];
    
    NSString *key = self.dataKeys[indexPath.row];
    NSString *value = [NSString stringWithFormat:@"%@", self.dataValues[indexPath.row]];
    cell.textLabel.text = [NSString stringWithFormat:@"%@: %@", key, value];
    
    return cell;
}

#pragma mark - UITableViewDelegate

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return @"患者信息详情";
}

@end
