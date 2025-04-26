#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
 * BPF map to store the round-robin index.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rr_index_map SEC(".maps");

/**
 * eBPF program to select a socket in round-robin among 4 sockets.
 */
SEC("sk_reuseport")
int select_sock(struct sk_reuseport_md *ctx)
{
    __u32 key = 0;
    __u32 *index;

    /** Look up the current round-robin index from the map. */
    index = bpf_map_lookup_elem(&rr_index_map, &key);
    if (!index)
        return SK_DROP;

    /** Select the socket based on the current index. */
    __u32 selected = *index;

    /** Update the index to the next socket (wrap around 4 sockets). */
    *index = (selected + 1) % 4;

    /** Return the selected socket index to the kernel. */
    return selected;
}

/** Specify GPL license. */
char _license[] SEC("license") = "GPL";
