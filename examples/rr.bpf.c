#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/**
 * eBPF program attached to sk_reuseport to perform basic load balancing.
 */
SEC("sk_reuseport")
int reuseport_prog(struct sk_reuseport_md *ctx) {
    /**
     * Generate a random 32-bit number using helper.
     * bpf_get_prandom_u32() provides a pseudo-random number.
     */
    __u32 rand = bpf_get_prandom_u32();
    
    /**
     * Decide which socket to select.
     * Assume there are 4 sockets bound to the same port.
     */
    int index = rand % 4; /** Pick socket index between 0 and 3 */

    /**
     * Attempt to select the socket based on calculated index.
     * NULL sock_map means kernel selects from the reuseport group.
     */
    int ret = bpf_sk_select_reuseport(ctx, NULL, &index, 0);

    /**
     * If selection failed, allow the packet to pass without rerouting.
     */
    if (ret < 0) {
        return SK_PASS;
    }

    /**
     * Always allow the connection to pass after selecting.
     */
    return SK_PASS;
}

/**
 * Required license declaration for eBPF programs.
 * "GPL" license allows using specific BPF helper functions.
 */
char _license[] SEC("license") = "GPL";
