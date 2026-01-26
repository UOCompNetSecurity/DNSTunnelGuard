bpftool cgroup detach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/unbound_guard

rm /sys/fs/bpf/unbound_guard
