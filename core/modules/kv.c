#include <string.h>
#include <rte_tcp.h>
#include "../module.h"

#define KV_SET "SET"
#define KV_GET "GET"
#define KV_ACK "ACK"
#define KV_ERR "ERR"
#define FIELD_LENGTH 8

/*
 * Hold one key and one value, each a string of length up to 7
 */
struct kv_priv {
    char[FIELD_LENGTH] key;
    char[FIELD_LENGTH] value;
}

struct kv_datagram {
    char[3] hdr;
    char[FIELD_LENGTH] key;
    char[FIELD_LENGTH] value;
}

static struct snobj *kv_init(
    struct module* m,
    struct snobj* arg
) {
    struct kv_priv* priv = (kv_priv*) get_priv(m);
    priv->key = malloc(sizeof(char)*FIELD_LENGTH);
    priv->value = malloc(sizeof(char)*FIELD_LENGTH);
}

static void kv_deinit(
    struct module* m
) {
    struct kv_priv* priv = (kv_priv*) get_priv(m);
    free(priv->key);
    free(priv->value);
}

static void kv_swap_fields(
    struct snbuf* pkt
) {
    // swap ipv4 header + ethernet header then call run_next_module
    // never mind about checksums
    
    struct ether_hdr* eth_hdr = snb_head_data(pkt);
    struct ether_addr tmp;
    memcpy(&tmp, &eth_hdr->d_addr, sizeof(struct ether_addr));
    memcpy(&eth_hdr->d_addr, &eth_hdr->s_addr, sizeof(struct ether_addr));
    memcpy(&eth_hdr->s_addr, &tmp, sizeof(struct ether_addr));

    struct ipv4_hdr* ip_hdr = eth_hdr + sizeof(struct ether_hdr);
    uint32_t tmp = ip_hdr->src_addr;
    ip_hdr->src_addr = ip_hdr->dst_addr;
    ip_hdr->dst_addr = tmp;
}

static struct snbuf* kv_err(
    struct snbuf* pkt,
    char[] key
) {
    struct kv_priv* priv = (kv_priv*) get_priv(m);
    
    kv_datagram resp;
    resp->hdr = KV_ACK;
    resp->key = key;
    resp->value = priv->key;
    
    kv_swap_fields(pkt);

    kv_datagram *data = (kv_datagram*)(snb_head_data(pkt)
        + sizeof(struct ether_hdr)
        + sizeof(struct ipv4_hdr)
        + sizeof(struct tcp_hdr));

    memcpy(data, &resp, sizeof(struct kv_datagram);
}

static struct snbuf* kv_ack(
    struct snbuf* pkt
) {
    // send a packet with key = priv->key and value = priv->value
    struct kv_priv* priv = (kv_priv*) get_priv(m);
    
    kv_datagram resp;
    resp->hdr = KV_ACK;
    resp->key = priv->key;
    resp->value = priv->value;

    kv_swap_fields(pkt);
        
    kv_datagram *data = (kv_datagram*)(snb_head_data(pkt)
        + sizeof(struct ether_hdr)
        + sizeof(struct ipv4_hdr)
        + sizeof(struct tcp_hdr));
    
    memcpy(data, &resp, sizeof(struct kv_datagram);
}

static void kv_get(
    struct snbuf* pkt,
    char[] key
) {
    struct kv_priv* priv = (kv_priv*) get_priv(m);

    int eq = strncmp(key, priv->key, FIELD_LENGTH);
    if (eq == 0) {
        kv_ack(pkt);
    }
    else {
        kv_err(pkt, key);
    }
}
    
static void kv_set(
    struct snbuf* pkt,
    char[] key, 
    char[] value
) {
    struct kv_priv* priv = (kv_priv*) get_priv(m);

    memcpy(priv->key, key, FIELD_LENGTH - 1);
    priv->key[FIELD_LENGTH - 1] = "\0";
    memcpy(priv->value, value, FIELD_LENGTH - 1);
    priv->value[FIELD_LENGTH - 1] = "\0";

    kv_ack(pkt);
}

static void kv_process_batch(
    struct module* this,
    struct pkt_batch* batch
) {
    struct pkt_batch out_batch;
    batch_clear(&out_batch);

    /*
     * A packet is an snbuf
     * batch->pkts is an array of snbuf's
     */
    for (int i = 0; i < batch->cnt; i++) {
        struct snbuf *pkt = batch->pkts[i];
        kv_datagram *data = (kv_datagram*)(snb_head_data(pkt)
            + sizeof(struct ether_hdr)
            + sizeof(struct ipv4_hdr)
            + sizeof(struct tcp_hdr));
        if (data->hdr == KV_SET) {
            kv_set(pkt, data->key, data->value);
        }
        else if (data->hdr == KV_GET) {
            kv_get(pkt, data->key);
        }
    }

    run_next_module(this, batch);
}

static const struct mclass kv = {
    .name = "KV",
    .priv_size = sizeof(struct kv_priv),
    .init = kv_init,
    .deinit = kv_deinit,
    .process_batch = kv_process_batch,
};

ADD_MCLASS(kv);
