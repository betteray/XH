#import <Foundation/Foundation.h>

@interface PreciseGCDTimer : NSObject
@property (nonatomic, copy) void (^triggerBlock)(void);
- (void)startDailyAtHour:(NSInteger)hour minute:(NSInteger)minute;
- (void)stop;
@end