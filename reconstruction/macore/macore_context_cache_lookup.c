/* CMusicalContext provider/TLS cache lookup corresponding to original
 * 0x51e10..0x51e8c, entered at 0x51e18.  The pthread/provider setup and the
 * cache-miss callback path are deliberately outside this source boundary. */
#include <stdint.h>

struct __attribute__((packed)) context_cache_node {
  float sample;
  unsigned char pad04[0x0c];
  uint64_t second;
  unsigned char pad18[0x98];
  struct context_cache_node *next;
  uint64_t first;
  unsigned char flag;
};

void *mobilelogic_context_cache_lookup(void *destination,
                                       struct context_cache_node *node,
                                       float sample,
                                       uint64_t first,
                                       uint64_t second,
                                       uint8_t flag) {
  while (node != 0) {
    if (node->sample == sample && node->first == first &&
        node->second == second && node->flag == flag) {
      volatile unsigned char *out = (volatile unsigned char *)destination;
      const volatile unsigned char *in =
          (const volatile unsigned char *)node;
      for (unsigned i = 0; i != 0xc1; ++i)
        out[i] = in[i];
      return node;
    }
    node = node->next;
  }
  return 0;
}
