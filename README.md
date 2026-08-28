# mlicense SDK for Go

Go 客户端授权 SDK，支持离线授权（授权文件 + 挑战码）。

## 安装

```bash
go get github.com/twangjie/mlicense-sdk-go
```

## 快速开始

```go
package main

import (
    "fmt"
    "log"

    mlicense "github.com/twangjie/mlicense-sdk-go"
)

func main() {
    client, err := mlicense.NewClient(mlicense.Config{
        ProductID:    "demo",
        PublicKeyPEM: `-----BEGIN PUBLIC KEY-----\n...`,
        LicensePath:  "./lic.dat",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // 验证授权文件
    if err := client.Verify(); err != nil {
        log.Fatal("授权验证失败:", err)
    }

    // 功能门控
    if !client.CheckFeature("gb28181_access") {
        log.Fatal("未授权 GB28181 功能")
    }

    // 限制检查
    if err := client.CheckLimit("max_streams", 10); err != nil {
        log.Fatal(err)
    }
}
```

## 如何选择授权方式

SDK 集成者（产品方）根据自身产品的复杂度，**选择一种**授权认证方式。选择标准：

| 场景 | 推荐方式 |
|------|----------|
| 产品功能简单，**只需判断是否已授权**，无需细分功能/限制 | **挑战码（简单场景）** |
| 产品较复杂，**需要细分功能门控与限制值**（如 channels/streams 数量、模块开关） | **授权文件**（或挑战码+授权文件） |

> 两者可并行支持，由产品方在集成时决定走哪条路径。

### 方式一：挑战码（简单产品）

无需 feature/limit 管理，只要验证应答码通过即完成授权，不落地授权文件。

```go
client, _ := mlicense.NewClient(mlicense.Config{
    ProductID:    "demo",
    PublicKeyPEM: pubKey,
})

// 1. 设备生成挑战码并告知管理员（同时需提供设备指纹 fp）
code, _ := client.GenerateChallengeCode()
fmt.Println("挑战码:", code)
fmt.Println("指纹:", client.GetFingerprint())

// 2. 管理员在后台凭挑战码 + 指纹生成应答码
// 3. 设备验证应答码，通过即激活
err := client.ActivateByResponse(responseCode, fingerprint)
if err != nil {
    log.Fatal("激活失败:", err)
}

// 已授权，且所有 feature/limit 不限制
fmt.Println(client.IsActivated()) // true
client.CheckFeature("any")        // true
client.CheckLimit("max_streams", 999) // nil
```

### 方式二：授权文件（复杂产品）

管理员下发完整授权文件（token 内含功能、限制、有效期），设备导入并验证 lic.dat。

```go
client, _ := mlicense.NewClient(mlicense.Config{
    ProductID:    "demo",
    PublicKeyPEM: pubKey,
    LicensePath:  "./lic.dat",
})

// 导入授权文件（落地到 lic.dat）
err := client.ImportLicense(tokenString)

// 验证
err = client.Verify()

// 功能门控
if !client.CheckFeature("gb28181_access") {
    log.Fatal("未授权 GB28181 功能")
}
// 限制检查
if err := client.CheckLimit("max_streams", 10); err != nil {
    log.Fatal(err)
}
```

### 方式三：挑战码 + 授权文件（复杂产品的离线激活）

产品需要 feature/limit 管理，同时希望走离线挑战码激活流程时，选择此方式：验证应答码后自动写入完整授权文件。

```go
// 管理员下发 responseCode + licenseToken（完整授权文件，含功能/限制/有效期）
err := client.ActivateByResponseWithToken(responseCode, licenseToken, fingerprint)
if err != nil {
    log.Fatal("激活失败:", err)
}
// 该方法验证应答码匹配授权文件内容后，
// 将 licenseToken 写入 lic.dat 并完成 Verify()。
// 之后可用 CheckFeature / CheckLimit 进行功能门控。
```

## API

| 方法 | 说明 |
|------|------|
| `NewClient(cfg)` | 创建客户端 |
| `Verify()` | 验证授权文件 |
| `GetStatus()` | 返回 "active"/"expired"/"no_license" |
| `GetLicense()` | 获取授权详情 |
| `GetFingerprint()` | 获取设备指纹 |
| `GetHardwareInfo()` | 获取硬件信息 |
| `CheckFeature(id)` | 检查功能是否启用 |
| `CheckLimit(id, current)` | 检查限制是否超限 |
| `GetFeatures()` | 获取已启用功能列表 |
| `GetLimits()` | 获取限制值映射 |
| `GenerateChallengeCode()` | 生成挑战码 |
| `ActivateByResponse(code, fp)` | 简单场景：验证应答码即激活（无 feature/limit） |
| `ActivateByResponseWithToken(code, token, fp)` | 复杂场景：验证应答码并写入完整授权文件 |
| `IsActivated()` | 是否已授权 |
| `ImportLicense(token)` | 导入授权文件 |

## 配置

```go
type Config struct {
    ProductID    string            // 产品可读标识（Slug，如 "demo"）（必填，除非密钥包包含）
    PublicKeyPEM string            // 公钥 PEM（必填，除非使用密钥包）
    LicensePath  string            // 授权文件路径，默认 "./lic.dat"
    ExtraKeys    map[string]string // 额外 kid→公钥 PEM 映射（密钥轮换后保留旧公钥验证旧 License）

    // 离线密钥包（可选，替代逐一配置 PublicKeyPEM/ExtraKeys）
    KeyBundle     string            // 内嵌密钥包 JSON 字符串
    KeyBundlePath string            // 密钥包文件路径
}
```

> **说明**：密钥包由 mlicense 管理后台（产品管理页 → 导出密钥包）或 `mlicense-cli keys export` 生成，格式含 `product_id`（Slug）、`public_key`、`kid`，**只含公钥、不含私钥**，可安全内嵌/分发给集成者。
> 若同时提供 `PublicKeyPEM` 与密钥包，`PublicKeyPEM` 作为主密钥，密钥包公钥作为附加密钥合并；`ProductID` 为空时回退使用密钥包中的 `product_id`。
> 面向集成者的密钥包完整使用说明见 [`server/doc/integrator-guide.md`](../../server/doc/integrator-guide.md)。

```go
// 方式一：直接配置（内嵌公钥）
client, _ := mlicense.NewClient(mlicense.Config{
    ProductID:    "demo",
    PublicKeyPEM: "-----BEGIN PUBLIC KEY-----...",
    LicensePath:  "/etc/demo/license.dat",
})

// 方式二：加载离线密钥包
client, _ := mlicense.NewClient(mlicense.Config{
    LicensePath:  "/etc/demo/license.dat",
    KeyBundlePath: "/etc/demo/demo-keys.json",
})

// 方式三：内嵌密钥包 JSON 字符串
client, _ := mlicense.NewClient(mlicense.Config{
    ProductID:    "demo",
    LicensePath:  "/etc/demo/license.dat",
    KeyBundleJSON: `{"product_id": "demo", "keys": [{"kid": "", "public_key": "-----BEGIN PUBLIC KEY-----..."}]}`,
})
```

## nolicense 模式

编译时添加 `nolicense` build tag 跳过所有授权检查：

```bash
go build -tags nolicense -o demo .
```

## 硬件指纹

SDK 自动采集设备指纹，支持 Linux、Windows、macOS：

- **Linux**: `/etc/machine-id` + `/sys/class/net/*/address`
- **Windows**: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` + `getmac`
- **macOS**: `ioreg` IOPlatformUUID + `ifconfig`

物理网卡筛选规则：排除 lo、docker、vmware、virtualbox、tap/tun、bridge、utun。

## 项目结构

```
sdk-go/
├── client.go          # 客户端生命周期 + 验证
├── config.go          # 配置
├── license.go         # 授权文件读写/导入
├── token.go           # Token 编解码
├── feature.go         # 功能门控
├── challenge.go       # 挑战码生成 + 应答码激活
├── nolicense.go       # nolicense stub
├── crypto/            # 加密原语
│   ├── ecdsa.go       # ECDSA 验签
│   ├── hmac.go        # HMAC 挑战码/应答码
│   └── fingerprint.go # 指纹计算
└── hardware/          # 跨平台硬件采集
    ├── hardware.go
    ├── linux.go
    ├── windows.go
    └── darwin.go
```
