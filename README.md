If rust analyzer is yelling at you, run `cargo build` so that the skeleton rust structure can be built.

TODO: Actually explain this so someone can understand it

To generate an updated `vmlinux.h`:

`bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./src/bpf/vmlinux.h`
