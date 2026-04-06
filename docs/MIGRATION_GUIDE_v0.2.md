# VRRP-go API 迁移指南：从 Panic 到 Error 模式

## 概览
为了遵循安全编码实践并提高库的健壮性，VRRP-go 网络层构造函数已从 **Advisory/Panic** 模式迁移为 **Compulsory/Error** 模式。

**变更日期**：2026-04-06
**状态**：强制性 (Breaking Change)

## 为什么进行此变更？
此前，网络初始化失败（如无法绑定多播地址或打开 Socket）会直接触发 `panic`。这在生产环境或作为上层库集成时会导致调用方进程崩溃，无法进行错误恢复或优雅降级。

## 涉及的变更点

### 1. IPv4 连接构造函数
- **旧接口**: `NewIPv4ConnMulticast(local, remote net.IP) IPConnection`
- **新接口**: `NewIPv4ConnMulticast(local, remote net.IP) (IPConnection, error)`
- **单播版**: `NewIPv4ConnUnicast` 同样增加了 `error` 返回值。

### 2. IPv6 连接构造函数
- **旧接口**: `NewIPv6ConMulticast(local, remote net.IP) *IPv6Con`
- **新接口**: `NewIPv6ConMulticast(local, remote net.IP) (IPConnection, error)`
- **单播版**: `NewIPv6ConUnicast` 同样增加了 `error` 返回值。

## 迁移步骤

### 步骤 A：更新构造调用
如果你直接使用了 `vrrp` 包的网络构造函数，请捕获并处理错误：

```go
// 以前 (旧)
conn := vrrp.NewIPv4ConnMulticast(local, remote)

// 现在 (新)
conn, err := vrrp.NewIPv4ConnMulticast(local, remote)
if err != nil {
    // 处理初始化失败 logic
    log.Fatalf("Failed to initialize VRRP connection: %v", err)
}
```

### 步骤 B：更新 VirtualRouter 初始化
如果你使用 `NewVirtualRouter`，虽然其函数签名未变，但由于内部现在会返回这些底层网络错误，你应该检查返回的 `error` 是否包含新的网络故障信息。

```go
vr, err := vrrp.NewVirtualRouter(vrid, "eth0", true, vrrp.IPv4)
if err != nil {
    // 现在这里会包含具体的底层网络错误，如 "bind: address already in use"
    return err
}
```

## 弃用说明 (Deprecation)
旧的返回单一值（且内部 panic）的私有方法和逻辑已被完全移除。建议所有用户立即升级到 v0.2.x 及其以上版本。
