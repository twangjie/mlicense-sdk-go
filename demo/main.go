package main

import (
	"fmt"
	"log"

	mlicense "github.com/twangjie/mlicense-sdk-go"
)

const privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINQzGmhk57/1uqVup8nIPp7fSCI/y4k7SFb4KZ7cwcj0oAoGCCqGSM49
AwEHoUQDQgAEnUBpeCxHjE3P9Ynf5X+ZoE5kgvSYTttj9MKv8b9kL6Z0iY3FsJkI
w4+Oadn/tS75Lw8HjYdkT/fp5CzCYBBXaw==
-----END EC PRIVATE KEY-----`

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnUBpeCxHjE3P9Ynf5X+ZoE5kgvSY
Tttj9MKv8b9kL6Z0iY3FsJkIw4+Oadn/tS75Lw8HjYdkT/fp5CzCYBBXaw==
-----END PUBLIC KEY-----`

const productID = "demo-product"

func must(err error) {
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}

func main() {
	must(demoChallengeSimple())
	must(demoChallengeWithToken())
	must(demoLicenseFile())
}

func demoChallengeSimple() error {
	fmt.Println("===== 方式一：挑战码（简单产品） =====")

	client, err := mlicense.NewClient(mlicense.Config{
		ProductID:    productID,
		PublicKeyPEM: publicKeyPEM,
		LicensePath:  "tmp_simple_lic.dat",
	})
	if err != nil {
		return err
	}

	// 1. 生成挑战码 + 指纹
	code, err := client.GenerateChallengeCode()
	if err != nil {
		return err
	}
	fp := client.GetFingerprint()
	fmt.Printf("  1. 挑战码: %s\n  2. 指纹:   %s\n", code, fp)

	// 2. 模拟管理员在后台生成应答码（仅绑定 挑战码+指纹）
	responseCode := simulateServerResponseCode(code, fp)
	fmt.Printf("  3. 管理后台应答码: %s\n", responseCode)

	// 3. 设备验证
	if err := client.ActivateByResponse(responseCode, fp); err != nil {
		return err
	}
	fmt.Printf("  4. 激活成功, IsActivated=%v, Status=%s\n", client.IsActivated(), client.GetStatus())
	fmt.Printf("  5. feature 不限制: CheckFeature(any)=%v, CheckLimit(max,999)=%v\n",
		client.CheckFeature("any"), client.CheckLimit("max", 999))

	client.Close()
	fmt.Println()
	return nil
}

// 方式三：挑战码 + 授权文件（复杂产品的离线激活）
func demoChallengeWithToken() error {
	fmt.Println("===== 方式三：挑战码 + 授权文件（复杂产品离线激活） =====")

	client, err := mlicense.NewClient(mlicense.Config{
		ProductID:    productID,
		PublicKeyPEM: publicKeyPEM,
		LicensePath:  "tmp_token_lic.dat",
	})
	if err != nil {
		return err
	}

	code, err := client.GenerateChallengeCode()
	if err != nil {
		return err
	}
	fp := client.GetFingerprint()
	fmt.Printf("  1. 挑战码: %s\n", code)

	features := []string{"gb28181_access", "onvif_access"}
	limits := map[string]int{"max_streams": 10}

	// 2. 管理员后台：应答码（设备授权，不绑定功能/限制）+ 完整授权文件（携带功能/限制）
	responseCode := simulateServerResponseCode(code, fp)
	token := simulateServerLicenseToken(features, limits, fp)
	fmt.Printf("  2. 应答码: %s\n  3. 授权文件 token: %s...\n", responseCode, token[:40])

	// 3. 设备验证应答码并写入授权文件
	if err := client.ActivateByResponseWithToken(responseCode, token, fp); err != nil {
		return err
	}
	fmt.Printf("  4. 激活成功, Status=%s\n", client.GetStatus())
	fmt.Printf("  5. CheckFeature(gb28181_access)=%v, CheckFeature(vod)=%v\n",
		client.CheckFeature("gb28181_access"), client.CheckFeature("vod"))
	fmt.Printf("  6. CheckLimit(max_streams,5)=%v, CheckLimit(max_streams,20)=%v\n",
		client.CheckLimit("max_streams", 5), client.CheckLimit("max_streams", 20))

	client.Close()
	fmt.Println()
	return nil
}

// 方式二：授权文件（复杂产品，直接导入）
func demoLicenseFile() error {
	fmt.Println("===== 方式二：授权文件（复杂产品直接导入） =====")

	client, err := mlicense.NewClient(mlicense.Config{
		ProductID:    productID,
		PublicKeyPEM: publicKeyPEM,
		LicensePath:  "tmp_import_lic.dat",
	})
	if err != nil {
		return err
	}

	fp := client.GetFingerprint()
	token := simulateServerLicenseToken([]string{"gb28181_access"}, map[string]int{"max_channels": 8}, fp)

	if err := client.ImportLicense(token); err != nil {
		return err
	}
	if err := client.Verify(); err != nil {
		return err
	}

	fmt.Printf("  1. 导入并验证成功, Status=%s\n", client.GetStatus())
	fmt.Printf("  2. CheckFeature(gb28181_access)=%v\n", client.CheckFeature("gb28181_access"))
	fmt.Printf("  3. CheckLimit(max_channels,8)=%v, CheckLimit(max_channels,9)=%v\n",
		client.CheckLimit("max_channels", 8), client.CheckLimit("max_channels", 9))
	fmt.Printf("  4. 授权详情 %+v\n", client.GetLicense())

	client.Close()
	fmt.Println()
	return nil
}
