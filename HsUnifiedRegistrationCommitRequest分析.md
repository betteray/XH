# HsUnifiedRegistrationCommitRequest 逆向分析文档

## 概述

`HsUnifiedRegistrationCommitRequest` 是协和医院 App 中用于提交统一挂号请求的类，继承自 `BaseRequest`。本文档详细分析其构造方式和发送流程。

---

## 1. 类结构

### 1.1 继承关系

```
HsUnifiedRegistrationCommitRequest
    └── BaseRequest
            └── NSObject
```

### 1.2 属性列表

| 属性名 | 类型 | 说明 | 地址 |
|--------|------|------|------|
| `schId` | NSString | 排班ID | getter: `0x100e3aee0` |
| `patId` | NSString | 患者ID | getter: `0x100e3aefc` |
| `hosPatCardNo` | NSString | 医院就诊卡号 | getter: `0x100e3af18` |
| `hosPatCardType` | NSString | 就诊卡类型 | getter: `0x100e3af34` |
| `patName` | NSString | 患者姓名 | getter: `0x100e3af50` |
| `phoneNo` | NSString | 手机号 | getter: `0x100e3af6c` |
| `cardNo` | NSString | 身份证号 | getter: `0x100e3af88` |
| `signalId` | NSString | 信号ID | getter: `0x100e3afa4` |
| `takeIndex` | NSString | 取号索引 | getter: `0x100e3afc0` |
| `expectTimeInterval` | NSString | 预期时间间隔 | getter: `0x100e3afdc` |
| `takePassword` | NSString | 取号密码 | getter: `0x100e3aff8` |
| `createTime` | NSString | 创建时间 | getter: `0x100e3b014` |
| `fb1` | NSString | 扩展字段 | getter: `0x100e3b030` |
| `language` | NSString | 语言(zh/en) | getter: `0x100e3b04c` |
| `subjectId` | NSString | 科室ID | getter: `0x100e3b068` |
| `deptId` | NSString | 部门ID | getter: `0x100e3b084` |
| `nonce` | NSString | 随机数(自动生成) | getter: `0x100e3b0a0` |
| `blackbox` | NSString | 设备指纹(风控) | getter: `0x100e3b0bc` |

---

## 2. 初始化流程

### 2.1 方法信息

- **方法**: `-[HsUnifiedRegistrationCommitRequest init]`
- **地址**: `0x100e3aab0`
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
        // 格式: {baseURL}/hs-xh-single-web/r/{srcId}/20044/200
        NSString *urlString = [NSString stringWithFormat:@"%@/r/%@", fullURL, srcId];
        urlString = [NSString stringWithFormat:@"%@/20044/200", urlString];
        [self setURLString:urlString];
        
        // 5. 设置响应数据解析类
        [self setDataClass:[HsRegisterModel class]];
        
        // 6. 设置设备指纹 (blackbox)
        [self setBlackbox:[NSUserDefaults driverToken]];
    }
    return self;
}
```

### 2.3 API 端点

- **路径**: `/hs-xh-single-web/r/{srcId}/20044/200`
- **接口编号**: `20044/200`
- **响应模型**: `HsRegisterModel`

---

## 3. 请求体构造

### 3.1 方法信息

- **方法**: `-[HsUnifiedRegistrationCommitRequest customHTTPBodyObject]`
- **地址**: `0x100e3acfc`
- **大小**: `0x1d8` (472 bytes)

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
        @"schId", 
        @"patId",
        @"patName",
        @"phoneNo",
        @"cardNo",
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
    "schId": "排班ID",
    "patId": "患者ID",
    "hosPatCardNo": "就诊卡号",
    "hosPatCardType": "卡类型",
    "patName": "患者姓名",
    "phoneNo": "手机号",
    "cardNo": "身份证号",
    "signalId": "信号ID",
    "takeIndex": "取号索引",
    "expectTimeInterval": "预期时间",
    "takePassword": "取号密码",
    "createTime": "创建时间",
    "fb1": "扩展字段",
    "language": "zh",
    "subjectId": "科室ID",
    "deptId": "部门ID",
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

签名计算涉及以下 7 个字段（按顺序）：

1. `nonce` - 随机数
2. `schId` - 排班ID
3. `patId` - 患者ID
4. `patName` - 患者姓名
5. `phoneNo` - 手机号
6. `cardNo` - 身份证号
7. `blackbox` - 设备指纹

### 4.3 相关签名函数

其他使用相同签名机制的请求类：

| 请求类 | 地址 |
|--------|------|
| `HsCommitRegisterRequest` | `0x100ce16f8` |
| `HsCommitRegReturnVisitRequest` | `0x100ce1ea8` |
| `HsCommitRegTodayRequest` | `0x100ce26b8` |
| `HsXHLoginRequest` | `0x100de2f80` |
| `HsRegistrationWaitlistSubmitRequest` | `0x100e20d5c` |
| `HsXHAddPatRequest` | `0x100538e0c` |

---

## 5. 请求发送流程

### 5.1 调用链

```
业务层调用
    ↓
[request startAsynchronously:] 或 [request start]
    ↓
-[BaseRequest start] @ 0x101c016b8
    ↓
NetworkInterceptorChain 拦截器链
    ↓
-[NetworkRequest startAsynchronously:networkBlock:] @ 0x101c07248
    ↓
AFNetworking HTTP 请求
```

### 5.2 BaseRequest.start 方法

```objc
- (void)start {
    if ([self remaining] >= 1 && [self callback]) {
        self.g_remaining--;
        
        // 取消之前的请求
        [[self network] cancleRequest];
        
        // 记录开始时间
        [self setHttpStartTime:CFAbsoluteTimeGetCurrent()];
        
        // 通过拦截器链处理
        [NetworkInterceptorChain intercept:self block:...];
        
        // 根据选项执行请求
        NSInteger option = [self option];
        NetworkRequest *network = [self network];
        id networkBlock = [self networkBlock];
        
        if (option == 2) {
            [network startSynchronously:self networkBlock:networkBlock];
        } else if (option == 4) {
            [network startAsynchronously:self networkBlock:networkBlock];
        } else {
            [network startAsyncUnsafely:self networkBlock:networkBlock];
        }
    }
}
```

### 5.3 NetworkRequest 发送

- 支持 SM4 ECB 加密（当 Header 包含 `yuntai_secure=true` 时）
- 加密密钥从 `[GMCryptFormat instance].keyString` 获取

---

## 6. Frida Hook 点

### 6.1 关键函数地址

| 函数 | 地址 | 用途 |
|------|------|------|
| `-[HsUnifiedRegistrationCommitRequest init]` | `0x100e3aab0` | 拦截请求初始化 |
| `-[HsUnifiedRegistrationCommitRequest customHTTPBodyObject]` | `0x100e3acfc` | 拦截请求体构造 |
| `-[BaseRequest start]` | `0x101c016b8` | 拦截请求发送 |
| `-[BaseRequest allBodyFields]` | `0x101c01db8` | 拦截请求参数 |
| `-[NetworkRequest startAsynchronously:networkBlock:]` | `0x101c07248` | 拦截网络请求 |
| 签名函数指针 | `0x1046C00C0` | Hook 签名算法 |

### 6.2 Frida Hook 示例

```javascript
// Hook 请求初始化
var initAddr = Module.findBaseAddress("YourApp").add(0x00e3aab0);
Interceptor.attach(initAddr, {
    onEnter: function(args) {
        console.log("[init] HsUnifiedRegistrationCommitRequest");
    },
    onLeave: function(retval) {
        console.log("[init] 返回: " + retval);
    }
});

// Hook 请求体构造
var bodyAddr = Module.findBaseAddress("YourApp").add(0x00e3acfc);
Interceptor.attach(bodyAddr, {
    onEnter: function(args) {
        this.self = args[0];
        console.log("[customHTTPBodyObject] 开始构造请求体");
    },
    onLeave: function(retval) {
        var dict = new ObjC.Object(retval);
        console.log("[customHTTPBodyObject] 请求体: " + dict.description());
    }
});

// Hook 签名函数
var signPtr = Module.findBaseAddress("YourApp").add(0x046C00C0);
var signFunc = signPtr.readPointer();
if (!signFunc.isNull()) {
    Interceptor.attach(signFunc, {
        onEnter: function(args) {
            console.log("[Sign] 签名字段: " + new ObjC.Object(args[0]));
            console.log("[Sign] 属性字典: " + new ObjC.Object(args[1]));
            console.log("[Sign] 密钥标识: " + new ObjC.Object(args[2]));
        },
        onLeave: function(retval) {
            console.log("[Sign] 签名结果: " + new ObjC.Object(retval));
        }
    });
}
```

---

## 7. 相关类

### 7.1 父类 BaseRequest

| 方法 | 地址 | 说明 |
|------|------|------|
| `init` | `0x101c01064` | 初始化 |
| `start` | `0x101c016b8` | 发送请求 |
| `propertyKeyValues` | `0x101c0124c` | 获取属性键值对 |
| `allBodyFields` | `0x101c01db8` | 获取请求体 |
| `allHeaderFields` | `0x101c01c94` | 获取请求头 |

### 7.2 响应模型

- **类名**: `HsRegisterModel`
- **用途**: 解析挂号提交响应

### 7.3 相关配置类

- **HsProxy**: 提供 API 基础配置（baseURL, srcId）
- **GMCryptFormat**: 提供加密密钥
- **NSUserDefaults+driverToken**: 提供设备指纹

---

## 8. 总结

`HsUnifiedRegistrationCommitRequest` 是一个标准的 POST 请求类，关键点：

1. **URL 构造**: 基于 HsProxy 配置动态拼接
2. **nonce 生成**: 去除连字符的小写 UUID
3. **签名计算**: 基于 7 个关键字段和密钥 "k9" 计算
4. **设备指纹**: 通过 blackbox 字段传递风控数据
5. **发送机制**: 通过 BaseRequest → NetworkRequest → AFNetworking 链式调用

---

*文档生成时间: 2026年1月11日*
*IDA Pro 逆向分析*
