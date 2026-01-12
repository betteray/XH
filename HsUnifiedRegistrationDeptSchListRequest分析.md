# HsUnifiedRegistrationDeptSchListRequest 逆向分析文档

## 概述

`HsUnifiedRegistrationDeptSchListRequest` 是协和医院 App 中用于获取统一挂号科室排班列表的请求类，继承自 `BaseRequest`。本文档详细分析其构造方式和发送流程。

---

## 1. 类结构

### 1.1 继承关系

```
HsUnifiedRegistrationDeptSchListRequest
    └── BaseRequest
            └── NSObject
```

### 1.2 属性列表

| 属性名 | 类型 | 说明 | getter 地址 | setter 地址 |
|--------|------|------|-------------|-------------|
| `docName` | NSString | 医生姓名 | `0x100e3b9cc` | `0x100e3b9dc` |
| `sectId` | NSString | 节段ID | `0x100e3b9e8` | `0x100e3b9f8` |
| `docId` | NSString | 医生ID | `0x100e3ba04` | `0x100e3ba14` |
| `schDate` | NSString | 排班日期 | `0x100e3ba20` | `0x100e3ba30` |
| `schType` | NSString | 排班类型 | `0x100e3ba3c` | `0x100e3ba4c` |
| `deptId` | NSString | 部门ID | `0x100e3ba58` | `0x100e3ba68` |
| `subjectId` | NSString | 科室ID | `0x100e3ba74` | `0x100e3ba84` |
| `todaySch` | NSString | 当日排班标识 | `0x100e3ba90` | `0x100e3baa0` |
| `hosDistId` | NSString | 医院院区ID | `0x100e3baac` | `0x100e3babc` |
| `language` | NSString | 语言(zh/en) | `0x100e3bac8` | `0x100e3bad8` |
| `subjectName` | NSString | 科室名称 | `0x100e3bae4` | `0x100e3baf4` |
| `dayType` | NSString | 日期类型 | `0x100e3bb00` | `0x100e3bb10` |
| `mediLevel` | NSString | 医疗级别 | `0x100e3bb1c` | `0x100e3bb2c` |
| `resNoType` | NSString | 资源号类型 | `0x100e3bb38` | `0x100e3bb48` |
| `nonce` | NSString | 随机数(自动生成) | `0x100e3bb54` | `0x100e3bb64` |
| `blackbox` | NSString | 设备指纹(风控) | `0x100e3bb70` | `0x100e3bb80` |

---

## 2. 初始化流程

### 2.1 方法信息

- **方法**: `-[HsUnifiedRegistrationDeptSchListRequest init]`
- **地址**: `0x100e3b5bc`
- **大小**: `0x24c` (588 bytes)

### 2.2 伪代码

```objc
- (instancetype)init {
    self = [super init];  // 调用 BaseRequest init
    if (self) {
        // 1. 获取 API 基础 URL
        NSURL *baseURL;
        if ([[HsProxy instance] api_baseURL]) {
            baseURL = [[HsProxy instance] api_baseURL];
        } else {
            baseURL = [NSURL URLWithString:@""];
        }
        
        // 2. 拼接路径
        NSURL *fullURL = [baseURL URLByAppendingPathComponent:@"hs-xh-single-web"];
        
        // 3. 获取 srcId
        NSString *srcId;
        if ([[HsProxy instance] srcId]) {
            srcId = [[HsProxy instance] srcId];
        } else {
            srcId = @"";
        }
        
        // 4. 构造完整 URL
        // 格式: {baseURL}/hs-xh-single-web/r/{srcId}/20002/103
        NSString *urlString = [NSString stringWithFormat:@"%@/r/%@", fullURL, srcId];
        urlString = [NSString stringWithFormat:@"%@/20002/103", urlString];
        [self setURLString:urlString];
        
        // 5. 设置响应数据解析类
        [self setDataClass:[HsDeptSchModel class]];
        
        // 6. 设置设备指纹 (blackbox)
        [self setBlackbox:[NSUserDefaults driverToken]];
    }
    return self;
}
```

### 2.3 API 端点

- **路径**: `/hs-xh-single-web/r/{srcId}/20002/103`
- **接口编号**: `20002/103`
- **响应模型**: `HsDeptSchModel`

---

## 3. 请求体构造

### 3.1 方法信息

- **方法**: `-[HsUnifiedRegistrationDeptSchListRequest customHTTPBodyObject]`
- **地址**: `0x100e3b814`
- **大小**: `0x1b8` (440 bytes)

### 3.2 伪代码

```objc
- (NSDictionary *)customHTTPBodyObject {
    // 1. 生成 nonce (去除连字符的小写 UUID)
    NSString *uuid = [[[NSUUID UUID] UUIDString] lowercaseString];
    NSString *nonce = [uuid stringByReplacingOccurrencesOfString:@"-" withString:@""];
    [self setNonce:nonce];
    
    // 2. 获取所有属性键值对
    NSDictionary *properties = [self propertyKeyValues];
    
    // 3. 创建可变字典
    NSMutableDictionary *bodyDict = [NSMutableDictionary dictionary];
    [bodyDict addEntriesFromDictionary:properties];
    
    // 4. 定义签名字段
    NSArray *signKeys = @[
        @"nonce",
        @"deptId", 
        @"subjectId",
        @"blackbox"
    ];
    
    // 5. 调用签名函数
    // 函数指针位于 off_1046C00C0 (运行时动态设置)
    NSString *sign = signFunction(signKeys, properties, @"k9");
    
    // 6. 添加签名到请求体
    bodyDict[@"sign"] = sign;
    
    return bodyDict;
}
```

### 3.3 请求体示例

```json
{
    "docName": "医生姓名",
    "sectId": "节段ID",
    "docId": "医生ID",
    "schDate": "2026-01-11",
    "schType": "排班类型",
    "deptId": "部门ID",
    "subjectId": "科室ID",
    "todaySch": "0或1",
    "hosDistId": "院区ID",
    "language": "zh",
    "subjectName": "科室名称",
    "dayType": "日期类型",
    "mediLevel": "医疗级别",
    "resNoType": "资源号类型",
    "nonce": "32位随机字符串",
    "blackbox": "设备指纹",
    "sign": "签名值"
}
```

---

## 4. 签名机制

### 4.1 签名函数

- **函数指针地址**: `0x1046C00C0` (`__common` 段，运行时填充)
- **签名参数**:
  - `参数1`: 签名字段数组
  - `参数2`: 属性字典
  - `参数3`: 密钥标识 `"k9"`

### 4.2 签名字段

签名计算涉及以下 4 个字段（按顺序）：

1. `nonce` - 随机数
2. `deptId` - 部门ID
3. `subjectId` - 科室ID
4. `blackbox` - 设备指纹

### 4.3 相关签名函数

其他使用相同签名机制的请求类：

| 请求类 | 地址 | 签名字段数量 |
|--------|------|--------------|
| `HsUnifiedRegistrationCommitRequest` | `0x100e3acfc` | 7 |
| `HsXHLoginRequest` | `0x100de2f80` | - |
| `HsXHAddPatRequest` | `0x100538e0c` | - |
| `HsXHBangDingPatRequest` | `0x10053a944` | - |
| `HsCommitRegisterRequest` | `0x100ce16f8` | - |
| `HsRegistrationWaitlistSubmitRequest` | `0x100e20d5c` | - |

---

## 5. 发送请求流程

### 5.1 调用方

- **方法**: `-[HsDeptScheduleGridBusinessHandler loadUnifiedRegistrationDeptSchList:]`
- **地址**: `0x100dfd3b4`
- **大小**: `0x31c` (796 bytes)

### 5.2 伪代码

```objc
- (void)loadUnifiedRegistrationDeptSchList:(id)context {
    DDDDataHandler *dataHandler = [[[self yt_context] dataHandler] viewModel];
    id viewModel = [dataHandler viewModel];
    
    // 1. 创建请求对象
    HsUnifiedRegistrationDeptSchListRequest *request = [[HsUnifiedRegistrationDeptSchListRequest alloc] init];
    
    // 2. 设置 deptId
    [request setDeptId:[[viewModel subjectModel] deptId]];
    
    // 3. 设置 subjectId
    [request setSubjectId:[[viewModel subjectModel] subjectId]];
    
    // 4. 设置语言（根据 sectTypeXh 判断）
    NSString *sectType = [viewModel sectTypeXh];
    if ([sectType isEqualToString:@"4"] || [sectType isEqualToString:@"5"]) {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *appLanguage = [defaults objectForKey:@"AppleLanguages"]; // 或类似 key
        if ([appLanguage isEqualToString:@"en"]) {
            [request setLanguage:@"en"];
        } else {
            [request setLanguage:@"zh"];
        }
    }
    
    // 5. 发送异步请求
    [request startAsynchronously:^(BaseResponse *response) {
        // 回调处理 (sub_100DFD6FC)
        if ([[response data] isKindOfClass:[HsDeptSchModel class]]) {
            HsDeptSchModel *model = [response data];
            
            // 更新 ViewModel 数据
            [[dataHandler viewModel] setNowDateStr:[model nowDateStr]];
            
            if ([model daytype1Schs]) {
                [[dataHandler viewModel] setAmArray:[NSMutableArray arrayWithArray:[model daytype1Schs]]];
            }
            if ([model daytype2Schs]) {
                [[dataHandler viewModel] setPmArray:[NSMutableArray arrayWithArray:[model daytype2Schs]]];
            }
            if ([model daytype4Schs]) {
                [[dataHandler viewModel] setNoonArray:[NSMutableArray arrayWithArray:[model daytype4Schs]]];
            }
            
            // 完成回调
            if (completionBlock) {
                completionBlock(context);
            }
        } else {
            // 失败回调
            if (completionBlock) {
                completionBlock(nil);
            }
        }
    }];
}
```

### 5.3 请求发送链

```
-[HsDeptScheduleGridBusinessHandler loadUnifiedRegistrationDeptSchList:]
    │
    ├── [[HsUnifiedRegistrationDeptSchListRequest alloc] init]
    │       └── URL: {baseURL}/hs-xh-single-web/r/{srcId}/20002/103
    │       └── DataClass: HsDeptSchModel
    │       └── blackbox: [NSUserDefaults driverToken]
    │
    ├── setDeptId: / setSubjectId: / setLanguage:
    │
    └── [request startAsynchronously:callback]
            │
            ├── -[BaseRequest setOption:4]  // 异步模式
            ├── -[BaseRequest setCallback:]
            └── -[BaseRequest start]
                    │
                    ├── [NetworkInterceptorChain intercept:block:]
                    │
                    └── -[NetworkRequest startAsynchronously:networkBlock:]
                            │
                            ├── 设置网络活动指示器
                            ├── 配置请求序列化器
                            ├── 获取 URL 和参数
                            │       └── -[BaseRequest allBodyFields]
                            │               └── -[customHTTPBodyObject]  // 生成签名
                            │
                            └── AFNetworking 发送请求
```

---

## 6. 响应模型

### 6.1 HsDeptSchModel 结构

| 属性名 | 类型 | 说明 | 地址 |
|--------|------|------|------|
| `nowDateStr` | NSString | 当前日期字符串 | `0x100cb52b8` |
| `daytype1Schs` | NSArray\<HsSchedulModel\> | 上午排班列表 | `0x100cb52dc` |
| `daytype2Schs` | NSArray\<HsSchedulModel\> | 下午排班列表 | `0x100cb5300` |
| `daytype4Schs` | NSArray\<HsSchedulModel\> | 中午排班列表 | `0x100cb5324` |
| `mediLevels` | NSArray | 医疗级别列表 | `0x100cb5348` |

### 6.2 modelClassInArray 映射

```objc
+ (NSDictionary *)modelClassInArray {
    return @{
        @"daytype1Schs": [HsSchedulModel class],
        @"daytype2Schs": [HsSchedulModel class],
        @"daytype4Schs": [HsSchedulModel class]
    };
}
```

---

## 7. BaseRequest 网络层

### 7.1 核心方法

| 方法 | 地址 | 说明 |
|------|------|------|
| `-[BaseRequest init]` | `0x101c01064` | 初始化，设置 NetworkRequest |
| `-[BaseRequest start]` | `0x101c016b8` | 启动请求 |
| `-[BaseRequest startAsynchronously:]` | `0x101c0183c` | 异步请求 |
| `-[BaseRequest startSynchronously:]` | `0x101c017f0` | 同步请求 |
| `-[BaseRequest allBodyFields]` | `0x101c01db8` | 获取请求体 |
| `-[BaseRequest propertyKeyValues]` | `0x101c0124c` | 获取属性键值对 |

### 7.2 BaseRequest init 流程

```objc
- (instancetype)init {
    self = [super init];
    if (self) {
        // 创建 NetworkRequest 实例
        self.network = [[NetworkRequest alloc] init];
        
        // 设置重试次数
        [self setRetry:1];
        
        // 生成请求ID (时间戳 + 随机数)
        NSTimeInterval time = [NSDate timeIntervalSinceReferenceDate];
        int random = arc4random() % 1000;
        NSString *requestId = [NSString stringWithFormat:@"%.f%zd", time, random];
        [self setRequestId:requestId];
        
        // 设置默认选项和超时
        [self setOption:1];
        [self setTimeout:30.0];
    }
    return self;
}
```

### 7.3 网络请求加密

当 Header 包含 `yuntai_secure: true` 时，HTTP Body 会使用 SM4 加密：

```objc
if ([headers[@"yuntai_secure"] isEqualToString:@"true"]) {
    NSData *body = [request HTTPBody];
    if (body) {
        NSString *keyString = [[GMCryptFormat instance] keyString];
        NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
        NSData *encrypted = [GMSm4Crypt ecb_encrypt:body keyData:keyData];
        NSData *base64 = [encrypted base64EncodedDataWithOptions:0];
        [mutableRequest setHTTPBody:base64];
    }
}
```

---

## 8. 相关类

### 8.1 同类型排班请求

| 类名 | 方法 | 地址 | 说明 |
|------|------|------|------|
| `HsDeptSchListRequest` | `init` | `0x100ce6d68` | 普通排班列表 |
| `HsReturnVisitDeptSchListRequest` | `init` | `0x100d0338c` | 复诊排班列表 |
| `HsUnifiedRegistrationDeptSchListRequest` | `init` | `0x100e3b5bc` | 统一挂号排班列表 |

### 8.2 调用此接口的 Handler

| 类名 | 方法 | 地址 |
|------|------|------|
| `HsDeptScheduleGridBusinessHandler` | `loadUnifiedRegistrationDeptSchList:` | `0x100dfd3b4` |
| `HsDeptScheduleGridBusinessHandler` | `loadDeptSchList:` | `0x100dfcd48` |
| `HsDeptScheduleGridBusinessHandler` | `loadReturnVisitDeptSchList:` | `0x100dfc708` |

---

## 9. 总结

`HsUnifiedRegistrationDeptSchListRequest` 是获取科室排班信息的核心请求：

1. **接口路径**: `/hs-xh-single-web/r/{srcId}/20002/103`
2. **签名字段**: `nonce`, `deptId`, `subjectId`, `blackbox` (共4个)
3. **响应模型**: `HsDeptSchModel`，包含上午/下午/中午三个时段的排班列表
4. **签名密钥**: 使用 `k9` 标识的密钥
5. **调用时机**: 在 `HsDeptScheduleGridBusinessHandler` 中加载科室排班时调用
