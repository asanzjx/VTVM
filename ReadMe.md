# ReadMe
基于 Intel CPU VT 实现 Win OS 虚拟化 

## 功能
1. IDT hook
2. Monitor Trap flag 监视
3. 基于 EPT page hook 实现 system call hook
4. 通过设置 MSR bitmaps 可实现监视特定 I/O port 的读写（可用于 anti-anti 虚拟机等）
5. 更优的 hook system-calls 方式 - in x64 disabling syscall in EFER and handle #UDs, 已设置好 vmcs 和 R/W MSR handle ，需要处理 emulate syscall/sysret(待实现)

## 注意的点
1. Compile for x64, realse, 兼容 win7/win10, 但需要设置单核 CPU(多核 CPU 需要在 LoadVM() 中额外增加处理)
2. 虚拟化的主要处理逻辑代码在 LoadVM() 函数中
3. 驱动卸载时未处理关闭虚拟机，所以卸载时会蓝屏，需提前做好快照，备份还原
4. 基于 EPT page hook 的 system hook 有一定几率会蓝屏
