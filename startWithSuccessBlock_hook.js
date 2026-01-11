/**
 * Frida Hook: -[BaseRequest startWithSuccessBlock:failureBlock:]
 * 
 * 用法: frida -U -f com.xiehe.pumch -l startWithSuccessBlock_hook.js
 */

if (ObjC.available) {
    console.log("[*] Frida Hook 启动...");

    var BaseRequest = ObjC.classes.BaseRequest;
    
    if (BaseRequest) {
        var methodName = "- startWithSuccessBlock:failureBlock:";
        var method = BaseRequest[methodName];
        
        if (method) {
            Interceptor.attach(method.implementation, {
                onEnter: function(args) {
                    var self = new ObjC.Object(args[0]);
                    var className = self.$className;
                    
                    console.log("\n" + "=".repeat(60));
                    console.log("[+] " + className + " startWithSuccessBlock:failureBlock:");
                    console.log("=".repeat(60));
                    
                    // 打印请求类信息
                    console.log("[*] 请求类: " + className);
                    
        
                    // 打印调用堆栈
                    console.log("\n[*] 调用堆栈:");
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                    
                    console.log("=".repeat(60) + "\n");
                },
                onLeave: function(retval) {
                    // 可选: 打印返回值
                }
            });
            
            console.log("[+] 已 Hook: -[BaseRequest startWithSuccessBlock:failureBlock:]");
        } else {
            console.log("[-] 方法不存在: " + methodName);
        }
    } else {
        console.log("[-] 类不存在: BaseRequest");
    }
    
    
} else {
    console.log("[-] Objective-C 运行时不可用");
}
