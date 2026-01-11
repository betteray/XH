#import "PreciseGCDTimer.h"

@implementation PreciseGCDTimer {
    dispatch_source_t _timer;
}

- (void)startDailyAtHour:(NSInteger)hour minute:(NSInteger)minute {
    [self stop];
    
    dispatch_queue_t queue = dispatch_queue_create("com.youapp.dailytimer", DISPATCH_QUEUE_SERIAL);
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    
    if (!_timer) return;
    
    // 计算首次触发时间
    NSDate *now = [NSDate date];
    NSCalendar *calendar = [NSCalendar currentCalendar];
    
    // 今天的目标时间
    NSDateComponents *targetComponents = [calendar components:
        NSCalendarUnitYear | NSCalendarUnitMonth | NSCalendarUnitDay
        fromDate:now];
    targetComponents.hour = hour;
    targetComponents.minute = minute;
    targetComponents.second = 0;
    
    NSDate *targetDate = [calendar dateFromComponents:targetComponents];
    
    // 如果已经过了目标时间，设置为明天
    if ([targetDate timeIntervalSinceDate:now] < 0) {
        targetDate = [calendar dateByAddingUnit:NSCalendarUnitDay value:1 toDate:targetDate options:0];
    }
    
    NSTimeInterval interval = [targetDate timeIntervalSinceDate:now];
    dispatch_time_t startTime = dispatch_walltime(NULL, (int64_t)(interval * NSEC_PER_SEC));
    
    // 使用dispatch_walltime可以避免系统休眠影响
    uint64_t repeatInterval = 24 * 60 * 60 * NSEC_PER_SEC;
    
    dispatch_source_set_timer(_timer, startTime, repeatInterval, 0);
    
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_timer, ^{
        [weakSelf handleTimerTrigger];
    });
    
    dispatch_resume(_timer);
    
    NSLog(@"Precise timer scheduled for %02ld:%02ld", (long)hour, (long)minute);
}

- (void)handleTimerTrigger {
    NSLog(@"Timer triggered at %@", [NSDate date]);
    
    // 确保在主线程执行
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.triggerBlock) {
            self.triggerBlock();
        }
    });
    
    // 可以添加业务逻辑
    [self performDailyTask];
}

- (void)performDailyTask {
    // 你的具体业务逻辑
    NSLog(@"Performing daily task at 15:00");
    
    // 示例：发送网络请求、更新数据等
    // [self updateData];
    // [self sendReport];
}

- (void)stop {
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }
}

- (void)dealloc {
    [self stop];
}

@end

