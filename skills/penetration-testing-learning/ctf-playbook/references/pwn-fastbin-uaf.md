# PWN Fastbin UAF (Dangling Pointer) Exploitation

## 适用场景
CTF PWN题给出用户管理系统（Register/Delete/Edit），free后未置NULL导致UAF。

## 识别模式 (静态分析)

### 漏洞特征
```c
// Delete函数：free了指针但没置NULL
free(users[id]->password);   // 释放密码缓冲区
free(users[id]);             // 释放结构体
// MISSING: users[id] = NULL  ← 悬垂指针!

// Edit函数：仅检查非NULL，直接写入已释放内存
if (users[id] != NULL)
    read(0, users[id]->password, users[id]->len);  // UAF!
```

### 结构体布局 (x86-64, 0x18 bytes)
```
[0x00] password_ptr   (heap pointer to malloc'd password)
[0x08] function_ptr    (show/display function pointer ← overwrite target)
[0x10] length field
```

## Fastbin Attack 利用链 (libc-2.23)

```
1. Register user0: password_size=0x18 → fastbin 0x20
2. Register user1: password_size=0x18 → fastbin 0x20
3. Delete user0: free(password0), free(struct0) → fastbin: struct0→NULL
4. Delete user1: free(password1), free(struct1) → fastbin: struct1→struct0→NULL
5. Edit user0 (UAF): overwrite struct0's fd → __malloc_hook - 0x23
6. Register twice: first gets struct0, second gets __malloc_hook area
7. Write one_gadget to __malloc_hook
8. Trigger malloc → one_gadget → shell
```

## Fastbin Size Check Bypass

`__malloc_hook - 0x23` 处字节形如 0x7fxxxx (libc 地址附近)，通过 size 校验。

## 静态分析技巧

```bash
objdump -T binary | grep -E "malloc|free|puts|read|printf"
objdump -d -M intel binary | sed -n '/<Delete>:/,/<.*>:/p'
# 看 Delete 中 free() 后是否有 mov QWORD PTR [global+idx*8], 0
# 没有 → 悬垂指针 → UAF
```

## 注意事项
- libc-2.23 无 tcache，直接进 fastbin
- libc-2.23 无 fastbin double-free 检测
- one_gadget ./libc-2.23.so 找可用 gadget
- 靶机无响应时先做完整静态分析 + exploit 编写
