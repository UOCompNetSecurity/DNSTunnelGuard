rc-update add cgroups boot

rc-service cgroups start

grep -qxF 'rc_cgroup_mode="unified"' /etc/conf.d/unbound || echo 'rc_cgroup_mode="unified"' >> /etc/conf.d/unbound

rc-service unbound restart

apk add clang llvm bpftool libbpf-dev make linux-lts-dev

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

mkdir -p /sys/fs/bpf/

