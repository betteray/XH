# HsXHPatientDetailRequest 分析

## 概述
`HsXHPatientDetailRequest` 是用于获取患者详情信息的网络请求类，继承自 `BaseRequest`。

## 类结构

### 属性
| 属性名 | 类型 | 说明 |
|-------|------|------|
| `hosId` | NSNumber | 医院 ID (从 srcId 转换) |
| `patId` | NSNumber/NSString | 患者 ID |

### 方法
- `-[HsXHPatientDetailRequest init]` @ `0x100549bb4`
- `-[HsXHPatientDetailRequest hosId]` @ `0x100549dd4`
- `-[HsXHPatientDetailRequest setHosId:]` @ `0x100549de4`
- `-[HsXHPatientDetailRequest patId]` @ `0x100549df0`
- `-[HsXHPatientDetailRequest setPatId:]` @ `0x100549e00`

## 请求构造流程

### 1. 初始化 (`-[HsXHPatientDetailRequest init]`)

```objc
- (instancetype)init {
    objc_super super = {self, [BaseRequest class]};
    self = objc_msgSendSuper(&super, @selector(init));
    
    if (self) {
        // 获取 API Base URL
        NSURL *baseURL;
        if ([[HsProxy instance] api_baseURL]) {
            baseURL = [[HsProxy instance] api_baseURL];
        } else {
            baseURL = [NSURL URLWithString:@""];
        }
        
        // 拼接路径: <baseURL>/hs-xh-single-web
        NSURL *url = [baseURL URLByAppendingPathComponent:@"hs-xh-single-web"];
        
        // 获取 srcId
        NSString *srcId;
        if ([[HsProxy instance] srcId]) {
            srcId = [[HsProxy instance] srcId];
        } else {
            srcId = @"";
        }
        
        // 构建完整 URL: <url>/r/<srcId>/20004/110
        NSString *urlString = [NSString stringWithFormat:@"%@/20004/110",
                               [NSString stringWithFormat:@"%@/r/%@", url, srcId]];
        
        [self setURLString:urlString];
        [self setDataClass:[HsXHPatientDetailModel class]];
    }
    return self;
}
```

### 2. API 接口格式

**完整 URL 格式:**
```
https://<api_baseURL>/hs-xh-single-web/r/<srcId>/20004/110
```

**示例:**
```
https://api.xiehe.com/hs-xh-single-web/r/1234/20004/110
```

## 请求发送流程

### 1. 调用入口 (`-[HsXHPatientDetailViewController detailRequest]`)

```objc
- (void)detailRequest {
    // 创建请求对象
    HsXHPatientDetailRequest *request = [[HsXHPatientDetailRequest alloc] init];
    
    // 设置 hosId (从 srcId 转换)
    NSString *srcId = [[HsProxy instance] srcId] ?: @"";
    [request setHosId:@([srcId integerValue])];
    
    // 设置 patId
    [request setPatId:[self patId]];
    
    // 显示加载状态
    if ([self detailModel]) {
        [HsProgressHud show];
    } else {
        [[[self view] loadingView] setState:1];  // 加载中状态
    }
    
    // 发送异步请求
    [request startAsynchronously:^(BaseRequest *req, id data, id unused, NSError *error) {
        // 回调处理...
    }];
}
```

### 2. BaseRequest 发送流程

```
startAsynchronously: 
    → setOption: 4 (异步模式)
    → setCallback: block
    → start
        → NetworkInterceptorChain intercept:block:  // 拦截器链
        → [NetworkRequest startAsynchronously:networkBlock:]
            → AFNetworking POST 请求
```

### 3. 请求参数

**HTTP 方法:** `POST`

**请求体 (Body):**
```json
{
    "hosId": <医院ID>,
    "patId": <患者ID>
}
```

**请求头:**
- OAuth 认证字段 (从 `NetworkProxy.OAuthFields` 获取)
- 其他自定义头信息

## 响应处理

### 响应模型: `HsXHPatientDetailModel`

| 属性 | 类型 | 说明 |
|------|------|------|
| `patId` | id | 患者 ID |
| `patId32` | id | 32位患者 ID |
| `patName` | NSString | 患者姓名 |
| `relation` | id | 与登录用户的关系 |
| `authStatus` | id | 认证状态 |
| `authStatusDesc` | NSString | 认证状态描述 |
| `accessPatId` | id | 访问患者 ID |
| `isDelete` | id | 是否已删除 |
| `documentId` | id | 证件 ID |
| `cardNo` | NSString | 卡号 |
| `cardNoType` | id | 卡号类型 |
| `cardNoTypeDesc` | NSString | 卡号类型描述 |
| `phoneNo` | NSString | 手机号 |
| `hasCanFaceAuth` | id | 是否可人脸认证 |
| `hasShowFaceAuthButton` | id | 是否显示人脸认证按钮 |
| `medInsCardNo` | NSString | 医保卡号 |
| `chnName` | NSString | 中文名 |

### 回调处理逻辑 (`sub_10054D21C`)

```objc
void callback(id block, int unused, BaseResponse *response) {
    if ([response error]) {
        // 错误处理
        [HsProgressHud dismissNoAnimated];
        if ([self detailModel]) {
            [[[self view] loadingView] setState:5];  // 隐藏状态
        } else {
            [[[self view] loadingView] setState:2];  // 错误状态
        }
    } else {
        // 成功处理
        [self setDetailModel:[response data]];
        [self initDataArry];
        [[[self view] loadingView] setState:5];
        
        // 初始化关系模型
        if (![self selectRelationShipModel]) {
            [self setSelectRelationShipModel:[[HsXHRelationshipModel alloc] init]];
        }
        [[self selectRelationShipModel] setRelationshipId:[[self detailModel] relation]];
        
        [[self tableView] reloadData];
        [self QRCodeRequest];   // 请求二维码
        [self showAlertView];   // 显示提示
    }
    [HsProgressHud dismissNoAnimated];
}
```

## 关联请求

`HsXHPatientDetailViewController` 中还包含以下相关请求:

| 方法 | 地址 | 说明 |
|------|------|------|
| `detailRequest` | `0x10054cff0` | 获取患者详情 |
| `patientNewsDetailRequest:callBack:` | `0x10054d4e0` | 获取患者最新详情 |
| `changePatientRelationShipRequest:` | `0x10054d9d0` | 修改患者关系 |
| `QRCodeRequest` | `0x10054dd9c` | 获取二维码 |
| `deletePatRequest` | `0x10054e2c4` | 删除患者 |
| `patAuthStateUpdateRequest` | `0x10054e6c0` | 更新认证状态 |
| `bindYiBaoRequest:` | `0x10054e824` | 绑定医保 |

## 网络层架构

```
HsXHPatientDetailRequest (请求参数封装)
        ↓
    BaseRequest (请求基类)
        ↓
NetworkInterceptorChain (拦截器链)
        ↓
    NetworkRequest (网络请求执行)
        ↓
   AFNetworking (底层网络库)
```

## Frida Hook 示例

```javascript
// Hook 请求发送
Interceptor.attach(ObjC.classes.HsXHPatientDetailRequest['- init'].implementation, {
    onEnter: function(args) {
        console.log('[HsXHPatientDetailRequest init] called');
    },
    onLeave: function(retval) {
        var request = new ObjC.Object(retval);
        console.log('[HsXHPatientDetailRequest] URLString:', request.URLString());
    }
});

// Hook 参数设置
Interceptor.attach(ObjC.classes.HsXHPatientDetailRequest['- setPatId:'].implementation, {
    onEnter: function(args) {
        console.log('[setPatId] patId:', new ObjC.Object(args[2]));
    }
});

// Hook 请求发送
Interceptor.attach(ObjC.classes.BaseRequest['- startAsynchronously:'].implementation, {
    onEnter: function(args) {
        var request = new ObjC.Object(args[0]);
        if (request.$className === 'HsXHPatientDetailRequest') {
            console.log('[HsXHPatientDetailRequest] Starting request...');
            console.log('  hosId:', request.hosId());
            console.log('  patId:', request.patId());
        }
    }
});
```
