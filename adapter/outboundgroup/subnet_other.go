//go:build !darwin && !linux

package outboundgroup

// CurrentNetwork is only implemented on macOS and Linux; elsewhere subnet groups use their default.
func CurrentNetwork() Network { return Network{} }
