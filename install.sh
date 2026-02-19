rc-update add cgroups boot

rc-service cgroups start

grep -qxF 'rc_cgroup_mode="unified"' /etc/conf.d/unbound || echo 'rc_cgroup_mode="unified"' >> /etc/conf.d/unbound

rc-service unbound restart

apk add clang llvm bpftool libbpf-dev make linux-lts-dev

mkdir -p /sys/fs/bpf/

gcc -fPIC -shared -o control_plane/libguard.so control_plane/bpf/libguard.c -lbpf

bpftool btf dump file /sys/kernel/btf/vmlinux format c > data_plane/vmlinux.h

bpftool cgroup detach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/ingress_guard
bpftool cgroup detach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/egress_guard

rm -f /sys/fs/bpf/ingress_guard
rm -f /sys/fs/bpf/egress_guard

clang -O2 -g -target bpf -c data_plane/ingress_guard.c -o data_plane/ingress_guard.o
clang -O2 -g -target bpf -c data_plane/egress_guard.c -o data_plane/egress_guard.o

bpftool prog load data_plane/ingress_guard.o /sys/fs/bpf/ingress_guard  
bpftool prog load data_plane/egress_guard.o /sys/fs/bpf/egress_guard 

bpftool cgroup attach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/ingress_guard
bpftool cgroup attach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/egress_guard

apk add python3 

cd control_plane

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "Tunnel Guard Installed"
