#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf_common.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int dummy_load_balance(struct __sk_buff *skb) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
