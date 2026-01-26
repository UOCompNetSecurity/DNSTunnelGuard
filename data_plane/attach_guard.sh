
bpftool prog load "$1" /sys/fs/bpf/unbound_filter

bpftool cgroup attach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/unbound_filter



