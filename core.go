// The ChaCha20 core transform.
// Optimized assembly implementations.

// +build amd64

package chacha20

func core(input, output *[size]uint32)
