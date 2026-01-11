// 协和医院App Frida Hook脚本 - NSURLSession网络请求版
// Bundle ID: com.hundsun.hospitalcloud.bj.unionmedicalcollegeHospital

console.log("[*] 协和医院App NSURLSession Hook脚本启动...");

// ========== NSURLSession网络请求Hook ==========

function hookNSURLSession() {
    console.log("[*] 开始Hook NSURLSession网络请求...");
    
    // Hook NSURLSession dataTaskWithRequest:completionHandler:
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
        console.log("[+] 找到NSURLSession类");
        
        // Hook dataTaskWithRequest:completionHandler:
        try {
            Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
                onEnter: function(args) {
                    var session = new ObjC.Object(args[0]);
                    var request = new ObjC.Object(args[2]);
                    var completionHandler = args[3];
                    
                    console.log("\n========== NSURLSession请求开始 ==========");
                    
                    // 获取URL
                    var url = request.URL();
                    if (url) {
                        console.log("[+] URL: " + url.absoluteString());
                    }
                    
                    // 获取HTTP方法
                    var method = request.HTTPMethod();
                    if (method) {
                        console.log("[+] Method: " + method.toString());
                    }
                    
                    // 获取请求头
                    var headers = request.allHTTPHeaderFields();
                    if (headers) {
                        console.log("[+] Headers: " + headers.description());
                    }
                    
                    // 获取请求体
                    var body = request.HTTPBody();
                    if (body && body.bytes && body.length() > 0) {
                        var bodyData = Memory.readUtf8String(body.bytes(), body.length());
                        console.log("[+] Body: " + bodyData);
                    }
                    
                    // 获取HTTPBodyStream
                    var bodyStream = request.HTTPBodyStream();
                    if (bodyStream) {
                        console.log("[+] 检测到HTTPBodyStream");
                    }
                    
                    this.url = url ? url.absoluteString().toString() : "Unknown";
                    this.method = method ? method.toString() : "GET";
                },
                onLeave: function(retval) {
                    console.log("[+] 创建DataTask完成: " + this.method + " " + this.url);
                    console.log("========== NSURLSession请求创建结束 ==========\n");
                }
            });
        } catch(e) {
            console.log("[-] Hook dataTaskWithRequest:completionHandler: 失败: " + e);
        }
        
        // Hook dataTaskWithURL:completionHandler:
        try {
            Interceptor.attach(NSURLSession["- dataTaskWithURL:completionHandler:"].implementation, {
                onEnter: function(args) {
                    var session = new ObjC.Object(args[0]);
                    var url = new ObjC.Object(args[2]);
                    var completionHandler = args[3];
                    
                    console.log("\n[+] NSURLSession URL请求: " + url.absoluteString());
                }
            });
        } catch(e) {
            console.log("[-] Hook dataTaskWithURL:completionHandler: 失败: " + e);
        }
    }
    
    // Hook NSURLSessionDataTask resume
    var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
    if (NSURLSessionDataTask) {
        console.log("[+] 找到NSURLSessionDataTask类");
        
        try {
            Interceptor.attach(NSURLSessionDataTask["- resume"].implementation, {
                onEnter: function(args) {
                    var task = new ObjC.Object(args[0]);
                    
                    console.log("\n========== 网络请求执行 ==========");
                    
                    // 获取原始请求
                    var originalRequest = task.originalRequest();
                    if (originalRequest) {
                        var url = originalRequest.URL();
                        if (url) {
                            console.log("[+] 执行请求: " + url.absoluteString());
                        }
                        
                        var method = originalRequest.HTTPMethod();
                        if (method) {
                            console.log("[+] 方法: " + method.toString());
                        }
                        
                        // 再次获取请求体（有些情况下这里才能获取到）
                        var body = originalRequest.HTTPBody();
                        if (body && body.bytes && body.length() > 0) {
                            var bodyData = Memory.readUtf8String(body.bytes(), body.length());
                            console.log("[+] 请求体: " + bodyData);
                        }
                    }
                    
                    // 获取当前请求（可能包含修改后的内容）
                    var currentRequest = task.currentRequest();
                    if (currentRequest && currentRequest !== originalRequest) {
                        console.log("[+] 当前请求与原始请求不同");
                        var currentBody = currentRequest.HTTPBody();
                        if (currentBody && currentBody.bytes && currentBody.length() > 0) {
                            var currentBodyData = Memory.readUtf8String(currentBody.bytes(), currentBody.length());
                            console.log("[+] 当前请求体: " + currentBodyData);
                        }
                    }
                    
                    console.log("========== 请求开始执行 ==========\n");
                },
                onLeave: function(retval) {
                    // Task resume完成
                }
            });
        } catch(e) {
            console.log("[-] Hook NSURLSessionDataTask resume 失败: " + e);
        }
    }
}

// Hook NSMutableURLRequest相关方法
function hookNSMutableURLRequest() {
    console.log("[*] 开始Hook NSMutableURLRequest...");
    
    var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (NSMutableURLRequest) {
        
        // Hook setHTTPBody:
        try {
            Interceptor.attach(NSMutableURLRequest["- setHTTPBody:"].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[0]);
                    var bodyData = new ObjC.Object(args[2]);
                    
                    if (bodyData && bodyData.bytes && bodyData.length() > 0) {
                        var bodyStr = Memory.readUtf8String(bodyData.bytes(), bodyData.length());
                        console.log("\n[+] 设置HTTP Body: " + bodyStr);
                        
                        // 尝试解析JSON
                        try {
                            var jsonObj = JSON.parse(bodyStr);
                            console.log("[+] JSON解析成功:");
                            console.log(JSON.stringify(jsonObj, null, 2));
                        } catch(e) {
                            // 不是JSON格式，直接显示原始数据
                        }
                    }
                }
            });
        } catch(e) {
            console.log("[-] Hook setHTTPBody 失败: " + e);
        }
        
        // Hook setValue:forHTTPHeaderField:
        try {
            Interceptor.attach(NSMutableURLRequest["- setValue:forHTTPHeaderField:"].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[0]);
                    var value = new ObjC.Object(args[2]);
                    var field = new ObjC.Object(args[3]);
                    
                    var valueStr = value ? value.toString() : "";
                    var fieldStr = field ? field.toString() : "";
                    
                    // 只记录重要的header
                    if (fieldStr.toLowerCase().indexOf("authorization") !== -1 ||
                        fieldStr.toLowerCase().indexOf("content-type") !== -1 ||
                        fieldStr.toLowerCase().indexOf("user-agent") !== -1 ||
                        fieldStr.toLowerCase().indexOf("x-") !== -1) {
                        console.log("[+] 设置Header: " + fieldStr + " = " + valueStr);
                    }
                }
            });
        } catch(e) {
            console.log("[-] Hook setValue:forHTTPHeaderField 失败: " + e);
        }
        
        // Hook setURL:
        try {
            Interceptor.attach(NSMutableURLRequest["- setURL:"].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[0]);
                    var url = new ObjC.Object(args[2]);
                    
                    if (url) {
                        var urlStr = url.absoluteString();
                        console.log("[+] 设置URL: " + urlStr);
                    }
                }
            });
        } catch(e) {
            console.log("[-] Hook setURL 失败: " + e);
        }
        
        // Hook setHTTPMethod:
        try {
            Interceptor.attach(NSMutableURLRequest["- setHTTPMethod:"].implementation, {
                onEnter: function(args) {
                    var request = new ObjC.Object(args[0]);
                    var method = new ObjC.Object(args[2]);
                    
                    if (method) {
                        console.log("[+] 设置HTTP方法: " + method.toString());
                    }
                }
            });
        } catch(e) {
            console.log("[-] Hook setHTTPMethod 失败: " + e);
        }
    }
}

// ========== 主函数 ==========

function main() {
    console.log("[*] ================================");
    console.log("[*] 协和医院App NSURLSession Hook脚本");
    console.log("[*] Bundle ID: com.hundsun.hospitalcloud.bj.unionmedicalcollegeHospital");
    console.log("[*] ================================");
    
    // 等待ObjC运行时加载完成
    if (ObjC.available) {
        console.log("[+] ObjC运行时可用");
        
        // Hook NSURLSession相关方法
        hookNSURLSession();
        hookNSMutableURLRequest();
        
        console.log("[+] NSURLSession Hook已设置完成");
        console.log("[*] 现在可以进行登录、预约等操作来触发网络请求...");
    } else {
        console.log("[-] ObjC运行时不可用");
    }
}

// 执行主函数
setTimeout(main, 1000);

console.log("[*] Hook脚本加载完成，等待触发...");