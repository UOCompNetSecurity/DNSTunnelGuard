bpftool cgroup detach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/unbound_guard

bpftool cgroup detach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/unbound_guard

clang -O2 -g -target bpf -I/usr/include -c guard.c -o guard.o

bpftool prog load guard.o /sys/fs/bpf/unbound_guard

bpftool cgroup attach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/unbound_guard

bpftool cgroup attach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/unbound_guard

echo "Guard attached"
