#import "XieheSettingsViewController.h"
#import "XieheSettings.h"

@implementation XieheSettingsViewController {
    UIDatePicker *_datePicker;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Xiehe 设置";
    self.view.backgroundColor = [UIColor whiteColor];

    _datePicker = [[UIDatePicker alloc] init];
    if (@available(iOS 13.4, *)) {
        _datePicker.preferredDatePickerStyle = UIDatePickerStyleWheels;
    }
    _datePicker.datePickerMode = UIDatePickerModeTime;

    NSCalendar *cal = [NSCalendar currentCalendar];
    NSDateComponents *comps = [[NSDateComponents alloc] init];
    comps.hour = XieheGetTriggerHour();
    comps.minute = XieheGetTriggerMinute();
    NSDate *date = [cal dateFromComponents:comps];
    if (date) {
        [_datePicker setDate:date animated:NO];
    }

    _datePicker.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_datePicker];
    [_datePicker.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor].active = YES;
    [_datePicker.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-20].active = YES;

    UIBarButtonItem *save = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave target:self action:@selector(onSave)];
    self.navigationItem.rightBarButtonItem = save;
    UIBarButtonItem *close = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel target:self action:@selector(onClose)];
    self.navigationItem.leftBarButtonItem = close;
}

- (void)onSave {
    NSCalendar *cal = [NSCalendar currentCalendar];
    NSDateComponents *comps = [cal components:(NSCalendarUnitHour|NSCalendarUnitMinute) fromDate:_datePicker.date];
    NSInteger h = comps.hour;
    NSInteger m = comps.minute;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:@(h) forKey:@"XieheTriggerHour"];
    [ud setObject:@(m) forKey:@"XieheTriggerMinute"];
    [ud synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:XieheTriggerTimeChangedNotification object:nil];
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)onClose {
    [self dismissViewControllerAnimated:YES completion:nil];
}

@end
