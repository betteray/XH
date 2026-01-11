# XieheAutoRegister - 协和医院自动挂号插件

基于 `HsUnifiedRegistrationCommitRequest` 逆向分析开发的 Theos 插件，可在指定时间自动发送挂号请求。

## 功能

- ✅ 定时触发（默认15:00）
- ✅ 自动构造挂号请求
- ✅ 支持配置文件
- ✅ 请求日志记录
- ✅ Hook 调试功能

## 文件结构

```
XieheAutoRegister/
├── Makefile                           # Theos 构建文件
├── control                            # Debian 包信息
├── Tweak.x                           # 主代码 (Logos 语法)
├── XieheAutoRegister.plist           # 注入目标配置
└── com.xiehe.autoregister.plist      # 运行时配置模板
```

## 编译

```bash
cd XieheAutoRegister
make package
```

## 安装

1. 将编译好的 .deb 文件传到设备
2. 使用 dpkg 安装：
   ```bash
   dpkg -i com.xiehe.autoregister_1.0.0_iphoneos-arm.deb
   ```
3. 复制配置文件到设备：
   ```bash
   cp com.xiehe.autoregister.plist /var/mobile/Library/Preferences/
   ```
4. 重启 App 或设备

## 配置

编辑 `/var/mobile/Library/Preferences/com.xiehe.autoregister.plist`：

| 参数 | 说明 | 示例 |
|------|------|------|
| `schId` | 排班ID | 从App中获取 |
| `patId` | 患者ID | 登录信息中获取 |
| `hosPatCardNo` | 就诊卡号 | |
| `hosPatCardType` | 卡类型 | |
| `patName` | 患者姓名 | |
| `phoneNo` | 手机号 | |
| `cardNo` | 身份证号 | |
| `subjectId` | 科室ID | |
| `deptId` | 部门ID | |
| `triggerHour` | 触发小时 | 15 |
| `triggerMinute` | 触发分钟 | 0 |
| `triggerSecond` | 触发秒 | 0 |

## 获取参数

### 方法1: 使用 Frida Hook

```javascript
// Hook 获取排班列表请求
Interceptor.attach(ObjC.classes.HsUnifiedRegistrationDeptSchListRequest['- init'].implementation, {
    onLeave: function(retval) {
        console.log('排班列表请求创建');
    }
});

// Hook 获取用户信息
Interceptor.attach(ObjC.classes.HsXHAppPatienInfoModel['- patId'].implementation, {
    onLeave: function(retval) {
        console.log('patId: ' + new ObjC.Object(retval));
    }
});
```

### 方法2: 抓包

使用 Charles 或 mitmproxy 抓取正常挂号请求，从中提取参数。

## 日志查看

```bash
# 实时查看日志
tail -f /var/log/syslog | grep XieheAutoReg
```

## 注意事项

1. **Bundle ID**: 默认配置为 `com.xiehe.pumch`，如有变化请修改 `XieheAutoRegister.plist`
2. **App 名称**: 默认为 `北京协和医院`，如有变化请修改 `Makefile`
3. **时间精度**: 定时器每秒检查一次，有2秒的触发窗口
4. **每日限制**: 每天只会触发一次，避免重复请求
5. **参数获取**: schId 等参数需要在挂号前从排班列表中动态获取

## 进阶使用

如需在触发时动态获取最新的 schId，可以先发送排班列表请求，解析响应后再发送挂号请求。参考代码：

```objc
// 先获取排班列表
HsUnifiedRegistrationDeptSchListRequest *listReq = [[%c(HsUnifiedRegistrationDeptSchListRequest) alloc] init];
[listReq setDeptId:kTargetDeptId];
[listReq setSubjectId:kTargetSubjectId];
[listReq startWithSuccessBlock:^(id req, id response, id data) {
    // 解析排班数据，获取 schId
    // 然后发送挂号请求
} failureBlock:^(id req, id response, id data, NSError *error) {
    XHLog(@"获取排班列表失败");
}];
```

## 免责声明

本项目仅供学习研究使用，请勿用于非法用途。使用本插件所产生的一切后果由使用者自行承担。
