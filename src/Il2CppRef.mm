// ============================================================================
//  IL2CPP Injection Reference Implementation
//  ---------------------------------------------------------------------------
//  用途：复现 Unity IL2CPP（iOS/arm64）进程内反射调用链的完整机制。
//  本文件是从样本 CounterFlameKAlert551.dylib 的机器码反推出来的等价实现，
//  去掉了原样本的远端授权/变现逻辑，只保留「如何调用托管代码」这一层。
//
//  构建（Theos）：
//     dylib 的 Makefile 设为 ARCHS = arm64 arm64e
//     注入方式二选一：
//       a) 二进制的 LC_LOAD_DYLIB 挂载 @executable_path/Frameworks/xxx.dylib
//       b) TrollStore / 越狱环境的 MobileSubstrate 自动加载
//
//  注意：IL2CPP 的 API 在 iOS 上不导出符号，必须 dlsym 从已加载的
//        UnityFramework 镜像里取（RTLD_DEFAULT 搜不到，Windows/Android 才有导出表）。
// ============================================================================

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

// ---------------------------------------------------------------------------
// 1. il2cpp API 类型定义
//    IL2CPP 在 iOS 上是内部符号，需要按 ABI 手写函数签名。
//    void* 统一表示 Il2CppDomain / Il2CppAssembly / Il2CppImage / Il2CppClass /
//    Il2CppMethodInfo / Il2CppString / Il2CppObject，宿主侧无需关心内部布局。
// ---------------------------------------------------------------------------

typedef void *(*t_il2cpp_domain_get)(void);
typedef void **(*t_il2cpp_domain_get_assemblies)(void *domain, size_t *count);
typedef void *(*t_il2cpp_assembly_get_image)(void *assembly);
typedef void *(*t_il2cpp_class_from_name)(void *image, const char *ns, const char *name);
typedef void *(*t_il2cpp_class_get_type)(void *klass);
typedef void *(*t_il2cpp_type_get_object)(void *type);
typedef void *(*t_il2cpp_class_get_method_from_name)(void *klass, const char *name, int argc);
typedef void *(*t_il2cpp_runtime_invoke)(void *method, void *obj, void **params, void **exc);
typedef void *(*t_il2cpp_string_new)(const char *s);
typedef uint16_t *(*t_il2cpp_string_chars)(void *str);
typedef int32_t (*t_il2cpp_string_length)(void *str);
typedef void *(*t_il2cpp_object_unbox)(void *obj);
typedef void *(*t_il2cpp_thread_attach)(void *domain);
typedef void *(*t_il2cpp_thread_current)(void);
typedef void (*t_il2cpp_gc_wbarrier_set_field)(void *obj, void **field, void *value);

// 15 个槽位，与原样本解析顺序完全对应（原样本把指针存在 __DATA 的
// 0x600660 / 0x6007c0 / 0x6007c8 / 0x6007d0 / 0x6006a0 / 0x6006a8 /
// 0x6007d8 / 0x6006d0 / 0x600698 / 0x6006c0 / 0x6006c8 / 0x600688 /
// 0x600668 / 0x600670 / 0x6007e0 这 15 个槽里，首次调用时惰性填充）。
static struct {
    t_il2cpp_domain_get                     domain_get;
    t_il2cpp_domain_get_assemblies          domain_get_assemblies;
    t_il2cpp_assembly_get_image             assembly_get_image;
    t_il2cpp_class_from_name                class_from_name;
    t_il2cpp_class_get_type                 class_get_type;
    t_il2cpp_type_get_object                type_get_object;
    t_il2cpp_class_get_method_from_name     class_get_method_from_name;
    t_il2cpp_runtime_invoke                 runtime_invoke;
    t_il2cpp_string_new                     string_new;
    t_il2cpp_string_chars                   string_chars;
    t_il2cpp_string_length                  string_length;
    t_il2cpp_object_unbox                   object_unbox;
    t_il2cpp_thread_attach                  thread_attach;
    t_il2cpp_thread_current                 thread_current;
    t_il2cpp_gc_wbarrier_set_field          gc_wbarrier_set_field;
} IL2;

static void *g_domain     = NULL;
static void *g_asm_image  = NULL;   // UnityFramework 镜像
static BOOL  g_resolved   = NO;

// ---------------------------------------------------------------------------
// 2. 惰性符号解析
//    UnityFramework 是 dlopen 出来的 rpath 库，直接 RTLD_DEFAULT 找不到它的
//    内部符号（非 export），必须 dlopen("@rpath/UnityFramework.framework/
//    UnityFramework") 拿到 handle，再逐个 dlsym。
//
//    原样本在这里做了两件事，值得复现：
//      a) 先 dlsym(RTLD_DEFAULT) 试一次，命中就直接用（省一次 dlopen）；
//      b) 失败再 dlopen 两个候选路径，RTLD_LAZY(1) 而不是 RTLD_NOW，
//         避免把所有依赖符号一次性解析导致启动变慢/失败。
// ---------------------------------------------------------------------------

static void *open_unity_framework(void) {
    void *h = dlopen("@rpath/UnityFramework.framework/UnityFramework", RTLD_LAZY);
    if (!h) h = dlopen("UnityFramework", RTLD_LAZY);
    return h;
}

static void *require_sym(void *handle, const char *name) {
    void *p = dlsym(RTLD_DEFAULT, name);
    if (!p && handle) p = dlsym(handle, name);
    if (!p) NSLog(@"[IL2REF] missing symbol %s", name);
    return p;
}

static BOOL il2cpp_resolve(void) {
    if (g_resolved) return YES;

    void *h = open_unity_framework();
    if (!h) {
        NSLog(@"[IL2REF] UnityFramework not loaded yet");
        return NO;
    }

    IL2.domain_get                 = (t_il2cpp_domain_get)                require_sym(h, "il2cpp_domain_get");
    IL2.domain_get_assemblies      = (t_il2cpp_domain_get_assemblies)     require_sym(h, "il2cpp_domain_get_assemblies");
    IL2.assembly_get_image         = (t_il2cpp_assembly_get_image)        require_sym(h, "il2cpp_assembly_get_image");
    IL2.class_from_name            = (t_il2cpp_class_from_name)           require_sym(h, "il2cpp_class_from_name");
    IL2.class_get_type             = (t_il2cpp_class_get_type)            require_sym(h, "il2cpp_class_get_type");
    IL2.type_get_object            = (t_il2cpp_type_get_object)           require_sym(h, "il2cpp_type_get_object");
    IL2.class_get_method_from_name = (t_il2cpp_class_get_method_from_name)require_sym(h, "il2cpp_class_get_method_from_name");
    IL2.runtime_invoke             = (t_il2cpp_runtime_invoke)            require_sym(h, "il2cpp_runtime_invoke");
    IL2.string_new                 = (t_il2cpp_string_new)                require_sym(h, "il2cpp_string_new");
    IL2.string_chars               = (t_il2cpp_string_chars)              require_sym(h, "il2cpp_string_chars");
    IL2.string_length              = (t_il2cpp_string_length)             require_sym(h, "il2cpp_string_length");
    IL2.object_unbox               = (t_il2cpp_object_unbox)              require_sym(h, "il2cpp_object_unbox");
    IL2.thread_attach              = (t_il2cpp_thread_attach)             require_sym(h, "il2cpp_thread_attach");
    IL2.thread_current             = (t_il2cpp_thread_current)            require_sym(h, "il2cpp_thread_current");
    IL2.gc_wbarrier_set_field      = (t_il2cpp_gc_wbarrier_set_field)     require_sym(h, "il2cpp_gc_wbarrier_set_field");

    // 只要核心 4 个到位就能跑
    if (!IL2.domain_get || !IL2.domain_get_assemblies ||
        !IL2.assembly_get_image || !IL2.class_from_name) {
        NSLog(@"[IL2REF] core symbols unresolved");
        return NO;
    }

    g_domain = IL2.domain_get();
    if (!g_domain) {
        NSLog(@"[IL2REF] domain is NULL (engine not initialized)");
        return NO;
    }

    // 关键：把当前线程挂到 GC 上，否则 runtime_invoke 会崩
    if (IL2.thread_attach) IL2.thread_attach(g_domain);

    g_resolved = YES;
    return YES;
}

// ---------------------------------------------------------------------------
// 3. 按程序集名定位 Il2CppImage
//    原样本的做法：遍历 domain_get_assemblies 返回的数组，对每个 assembly
//    取 image，再取 image 名字比对。这里没有 il2cpp_image_get_name 的依赖，
//    所以退一步：只取第一个（通常是 mscorlib）以外的都试，用 class_from_name
//    的返回值判定命中——这也是原样本的兜底策略。
//
//    更稳的做法是 dlsym 出 il2cpp_image_get_name 后按名字精确匹配，
//    这里两种都给出。
// ---------------------------------------------------------------------------

typedef const char *(*t_il2cpp_image_get_name)(void *image);

static void *image_for_assembly_named(NSString *wanted) {
    if (!g_domain) return NULL;

    t_il2cpp_image_get_name image_get_name =
        (t_il2cpp_image_get_name)require_sym(open_unity_framework(), "il2cpp_image_get_name");

    size_t count = 0;
    void **asms = IL2.domain_get_assemblies(g_domain, &count);
    if (!asms) return NULL;

    void *fallback = NULL;
    for (size_t i = 0; i < count; i++) {
        void *img = IL2.assembly_get_image(asms[i]);
        if (!img) continue;
        if (!fallback) fallback = img;
        if (image_get_name) {
            const char *n = image_get_name(img);
            if (n && wanted && [wanted isEqualToString:[NSString stringWithUTF8String:n]])
                return img;
        }
    }
    // 没拿到 image_get_name 时用 fallback（Unity 里 Assembly-CSharp 常在最前）
    return fallback;
}

// ---------------------------------------------------------------------------
// 4. 调用托管方法
//    il2cpp_runtime_invoke 的 ABI：
//      void* il2cpp_runtime_invoke(MethodInfo* method, void* obj,
//                                  void** params, Il2CppException** exc)
//    - obj     : 实例方法传 this，静态方法传 NULL
//    - params  : void* 数组，**每个元素是该参数值的地址**（不是值本身）
//                基本类型传入栈变量地址；引用类型（string/object）直接传指针
//    - exc     : 传出异常对象，非 NULL 表示托管侧抛了异常
//    返回值是 boxed 的 Il2CppObject*，值类型需 object_unbox 取地址。
// ---------------------------------------------------------------------------

static void *invoke_method(void *klass,
                           const char *method_name,
                           int argc,
                           void **args,
                           void *instance,
                           void **out_exc) {
    if (!klass) return NULL;
    void *method = IL2.class_get_method_from_name(klass, method_name, argc);
    if (!method) {
        NSLog(@"[IL2REF] method not found: %s/%d", method_name, argc);
        return NULL;
    }
    void *exc = NULL;
    void *ret = IL2.runtime_invoke(method, instance, args, &exc);
    if (out_exc) *out_exc = exc;
    if (exc) {
        NSLog(@"[IL2REF] managed exception in %s", method_name);
        return NULL;
    }
    return ret;
}

static void *find_class(const char *ns, const char *name) {
    if (!g_asm_image) g_asm_image = image_for_assembly_named(@"Assembly-CSharp");
    if (!g_asm_image) return NULL;
    return IL2.class_from_name(g_asm_image, ns, name);
}

// 取静态属性 getter（原样本大量使用 get_/set_ 前缀的反射调用）
static void *get_static_prop(const char *ns, const char *cls, const char *prop) {
    void *klass = find_class(ns, cls);
    if (!klass) return NULL;
    char buf[128];
    snprintf(buf, sizeof(buf), "get_%s", prop);
    return invoke_method(klass, buf, 0, NULL, NULL, NULL);
}

// ---------------------------------------------------------------------------
// 5. Unity 就绪探测 + 重试
//    原样本的 [CF-KAlert551] runtime ready=%d 就是这个：
//    IL2CPP 在 App 启动早期 domain 还不存在，必须轮询等 Unity 起来。
//    一旦 resolve 成功就停，失败按退避重试。
// ---------------------------------------------------------------------------

static BOOL unity_is_ready(void) {
    if (g_resolved) return YES;
    if (!il2cpp_resolve()) return NO;
    // domain 有了还不够，class_from_name 能取到 UnityEngine.CoreModule 才算真就绪
    void *img = image_for_assembly_named(@"UnityEngine.CoreModule");
    return img != NULL || find_class("UnityEngine", "Application") != NULL;
}

static void start_ready_loop(void (^onReady)(void)) {
    __block NSUInteger attempt = 0;
    __block void (^tick)(void);
    tick = ^{
        attempt++;
        if (unity_is_ready()) {
            NSLog(@"[IL2REF] runtime ready after %lu attempts", (unsigned long)attempt);
            if (onReady) onReady();
            return;
        }
        if (attempt > 600) {           // 约 60s 上限
            NSLog(@"[IL2REF] runtime never became ready");
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), tick);
    };
    tick();
}

// ---------------------------------------------------------------------------
// 6. 示例：读取一个托管对象的字段 / 调用实例方法
//    gc_wbarrier_set_field 的用途：直接把托管引用写进托管对象的字段槽。
//    这比 setter 更底层，原样本用它来"静默"写入装备/库存数据。
//
//    字段偏移无法从托管侧直接得知，工程上的做法是：
//      il2cpp_class_get_field_from_name -> il2cpp_field_get_offset。
//    这里给出签名，留作扩展点。
// ---------------------------------------------------------------------------

typedef void *(*t_il2cpp_class_get_field_from_name)(void *klass, const char *name);
typedef size_t (*t_il2cpp_field_get_offset)(void *field);

static void set_object_field(void *obj, void *klass, const char *field_name, void *value) {
    t_il2cpp_class_get_field_from_name get_field =
        (t_il2cpp_class_get_field_from_name)require_sym(open_unity_framework(), "il2cpp_class_get_field_from_name");
    t_il2cpp_field_get_offset get_offset =
        (t_il2cpp_field_get_offset)require_sym(open_unity_framework(), "il2cpp_field_get_offset");
    if (!get_field || !get_offset || !obj || !klass) return;

    void *f = get_field(klass, field_name);
    if (!f) return;
    size_t off = get_offset(f);
    IL2.gc_wbarrier_set_field(obj, (void **)((uint8_t *)obj + off), value);
}

// ---------------------------------------------------------------------------
// 7. 注入入口
//    时机选择（原样本用的是 b 方案，构造函数 + 定时器）：
//      a) __attribute__((constructor)) —— dylib 加载即执行，此时 Unity 未起
//      b) MobileSubstrate 的 %ctor            —— 同上
//      c) 监听 UIApplicationDidFinishLaunchingNotification 后再起轮询 —— 更稳
//    这里用 c，配合 5 的重试循环。
// ---------------------------------------------------------------------------

__attribute__((constructor))
static void il2ref_init(void) {
    NSLog(@"[IL2REF] dylib loaded, waiting for Unity");

    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *note) {
        start_ready_loop(^{
            // ---- 就绪回调：在这里做你的运行时逻辑 ----
            // 只读探测，不写任何游戏数据：
            void *app = find_class("UnityEngine", "Application");
            if (app) {
                void *v = invoke_method(app, "get_version", 0, NULL, NULL, NULL);
                if (v && IL2.string_chars) {
                    uint16_t *w = IL2.string_chars(v);
                    int32_t len = IL2.string_length(v);
                    NSMutableString *s = [NSMutableString string];
                    for (int32_t i = 0; i < len && w; i++) [s appendFormat:@"%C", (unichar)w[i]];
                    NSLog(@"[IL2REF] Unity version = %@", s);
                }
            }
            NSLog(@"[IL2REF] reference implementation active (read-only probe)");
        });
    }];
}
