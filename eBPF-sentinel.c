#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

// Define a struct for the packet features you want to send to userspace.
// This must exactly match the Go struct in your userspace application.
struct event {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
};

// 1. A hash map to store denylisted source IPs.
// The Go app will write to this map, and the eBPF program will read from it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Source IP
    __type(value, __u8);  // A simple flag (e.g., 1 for blocked)
} denylist_map SEC(".maps");

// 2. A ring buffer to send packet metadata to the Go userspace application.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // We only handle IPv4 for simplicity.
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    // --- Denylist Check ---
    // Check if the source IP is in our denylist map.
    if (bpf_map_lookup_elem(&denylist_map, &ip->saddr)) {
        // IP is on the denylist, drop the packet immediately.
        return XDP_DROP;
    }

    // --- Send to Userspace for Analysis ---
    // For this example, we only analyze TCP packets.
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }

    // Reserve space on the ring buffer for our event struct.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return XDP_PASS; // Not enough space, pass the packet.
    }

    // Populate the event with packet features.
    e->src_ip = ip->saddr;
    e->dest_ip = ip->daddr;
    e->src_port = bpf_ntohs(tcp->source);
    e->dest_port = bpf_ntohs(tcp->dest);

    // Submit the event to the ring buffer for the Go app to read.
    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

