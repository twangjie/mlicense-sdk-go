//go:build !nolicense

package mlicense

import "fmt"

// CheckFeature reports whether a feature is enabled. In the simple
// challenge-activated mode (no license file / no feature gating), every feature
// is considered enabled.
func (c *Client) CheckFeature(feature string) bool {
	if c.activated {
		return true
	}
	if c.license == nil {
		return false
	}
	for _, f := range c.license.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// CheckLimit reports whether a limit is exceeded. In the simple
// challenge-activated mode there is no limit enforcement.
func (c *Client) CheckLimit(limitID string, current int) error {
	if c.activated {
		return nil
	}
	if c.license == nil {
		return nil
	}
	maxVal, exists := c.license.Limits[limitID]
	if !exists {
		return nil
	}
	if current > maxVal {
		return fmt.Errorf("limit %s exceeded: current=%d, max=%d", limitID, current, maxVal)
	}
	return nil
}

func (c *Client) GetFeatures() []string {
	if c.license == nil {
		return nil
	}
	return c.license.Features
}

func (c *Client) GetLimits() map[string]int {
	if c.license == nil {
		return nil
	}
	return c.license.Limits
}
