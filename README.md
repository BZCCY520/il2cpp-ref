# il2cpp-ref

Unity IL2CPP 注入参考实现 + Windows 侧 Mach-O 注入工具。

本仓库是用 GitHub Actions 的 macOS runner 编译 iOS dylib，再回 Windows 侧注入 IPA 的最小可用管线。

## 背景

本工程源自对一个 Unity IL2CPP（arm64）iOS 样本的逆向分析，目的是复现「进程内反射调用托管代码」这一层机制。
样本内第三方模块的实现细节已剥离，只保留通用基础设施。

## 目录

```
src/Il2CppRef.mm        参考实现（Objective-C++）
tools/inject_dylib.py   IPA 注入器（纯 Python，Windows 可跑）
.github/workflows/      构建 workflow（macos-14）
```

## 编译

推到 GitHub 后，Actions 页面手动 Run workflow。

- 只出 dylib：`game_ipa_url` 留空
- 同时出注入好的 IPA：填原 IPA 直链

产物在 workflow 的 Artifacts 里下载：
- `Il2CppRef-dylib`（arm64 + arm64e fat binary）
- `injected-ipa`（可选）

## 机制要点

### 1. iOS 上 il2cpp API 不导出

必须 dlopen UnityFramework 拿 handle 再 dlsym：

```objc
dlopen("@rpath/UnityFramework.framework/UnityFramework", RTLD_LAZY)
dlsym(handle, "il2cpp_domain_get")
```

`RTLD_DEFAULT` 搜不到，因为符号不在导出表里。

### 2. 15 个符号的依赖顺序

```
domain_get                    → 拿 Il2CppDomain
domain_get_assemblies         → 拿 assembly 数组
assembly_get_image            → 每个 assembly 对应一个 image
image_get_name                → 按名字定位 Assembly-CSharp
class_from_name               → (image, ns, name) → Il2CppClass*
class_get_method_from_name    → (class, name, argc) → MethodInfo*
runtime_invoke                → 真正执行
```

### 3. runtime_invoke 的参数布局（易错）

```c
void* il2cpp_runtime_invoke(MethodInfo* method, void* obj,
                            void** params, Il2CppException** exc);
```

- `params` 是 `void**`，**每个元素存放的是「参数值的地址」，不是值本身**
- 基本类型：传栈变量地址
- 引用类型（string / object）：直接传对象指针
- 静态方法 `obj` 传 NULL
- 返回值是 boxed 对象，值类型要用 `object_unbox` 取地址

### 4. 线程必须 attach

```objc
il2cpp_thread_attach(domain);
```

不 attach 直接 invoke 会崩，因为 GC 不认识这个线程。

### 5. 启动时机

IL2CPP 在 App 启动早期 domain 还不存在。必须轮询：

```objc
UIApplicationDidFinishLaunchingNotification → 开始轮询 → domain + class 可解析才算就绪
```

## Windows 侧注入

不需要 macOS 工具链：

```powershell
python tools/inject_dylib.py `
  --ipa input.ipa `
  --dylib Il2CppRef.dylib `
  --out output.ipa
```

注入策略（按优先级）：

1. **复用空槽位**：如果主二进制里有被清空路径的 `LC_LOAD_WEAK_DYLIB`（80 字节），原地改指新 dylib。`ncmds` / `sizeofcmds` / 所有段偏移都不变，零结构风险。
2. **padding 追加**：load command 区尾部有空间时追加一条 `LC_LOAD_DYLIB`。
3. **两者都没有**：报错退出，不做段重排（会损坏二进制）。

同时会清空 `LC_CODE_SIGNATURE`，并删除 `_CodeSignature`，等待重签。

## 安装

产物签名已失效。安装前必须用自己的证书重签：

- **TrollStore**：直接安装（免签）
- **Sideloadly / AltStore**：自动重签
- **手动**：`codesign -f -s "证书" --entitlements ent.plist Payload/Xxx.app`

## 当前能力边界

参考实现只做**只读探测**：

```
[IL2REF] dylib loaded, waiting for Unity
[IL2REF] runtime ready after N attempts
[IL2REF] Unity version = ...
[IL2REF] reference implementation active (read-only probe)
```

这是一条可运行的注入管线，可以在 `start_ready_loop` 的就绪回调里挂自己的分析逻辑
（读字段、抓调用栈、打日志、监控状态变化）。

## 免责

仅用于自有应用的兼容性测试与安全研究。不用于绕过任何在线服务或游戏内购。
