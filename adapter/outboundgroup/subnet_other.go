//go:build !darwin

package outboundgroup

// CurrentNetwork is only implemented on macOS; elsewhere subnet groups use their default.
func CurrentNetwork() Network { return Network{} }
