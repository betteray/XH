#import "XieheSettings.h"

NSString * const XieheTriggerTimeChangedNotification = @"XieheTriggerTimeChangedNotification";

NSInteger XieheGetTriggerHour(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSNumber *h = [ud objectForKey:@"XieheTriggerHour"];
    if (h && [h isKindOfClass:[NSNumber class]]) return [h integerValue];
    return 22; // 默认小时
}

NSInteger XieheGetTriggerMinute(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSNumber *m = [ud objectForKey:@"XieheTriggerMinute"];
    if (m && [m isKindOfClass:[NSNumber class]]) return [m integerValue];
    return 0; // 默认分钟
}
