//go:build nolicense

package mlicense

import (
	"github.com/twangjie/mlicense-sdk-go/hardware"
)

type Client struct {
	config Config
}

func NewClient(cfg Config) (*Client, error) {
	return &Client{config: cfg}, nil
}

func (c *Client) Verify() error {
	return nil
}

func (c *Client) GetLicense() *TokenPayload {
	return nil
}

func (c *Client) GetStatus() string {
	return "active"
}

func (c *Client) GetFingerprint() string {
	return ""
}

func (c *Client) GetHardwareInfo() *hardware.HardwareInfo {
	return nil
}

func (c *Client) Close() {
}

func (c *Client) CheckFeature(feature string) bool {
	return true
}

func (c *Client) CheckLimit(limitID string, current int) error {
	return nil
}

func (c *Client) GetFeatures() []string {
	return nil
}

func (c *Client) GetLimits() map[string]int {
	return nil
}

func (c *Client) GenerateChallengeCode() (string, error) {
	return "", nil
}

func (c *Client) ActivateByResponse(responseCode string, fingerprint string) error {
	return nil
}

func (c *Client) ActivateByResponseWithToken(responseCode string, licenseToken string, fingerprint string) error {
	return nil
}

func (c *Client) IsActivated() bool {
	return true
}

func (c *Client) ImportLicense(token string) error {
	return nil
}
