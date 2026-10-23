/* MACore original SHA256
 * 88a8d93c6cb4b411648601efdfc5ca2863c3b833339e55e2470369df1d3bc9d5.
 * Real scalar source for three complete original leaf functions.
 * These are OR-fold hashes, not XOR or arithmetic-addition hashes.
 * Ordinary readable storage is required; no alignment requirement.
 */
#include <stdint.h>

static uint64_t little64(const unsigned char *p) {
  uint64_t value = 0;
  for (unsigned i = 0; i != 8; ++i)
    value |= (uint64_t)p[i] << (8 * i);
  return value;
}

/* Original 0x505fc..0x5072c: HashMAMidiEventRepresentationDiff. */
uint64_t mobilelogic_macore_event_diff_hash(const void *event) {
  const unsigned char *p = event;
  return little64(p) | little64(p + 8) | little64(p + 16);
}

/* Original 0x4fe90..0x4ffc0: const std::hash::operator() ABI.
 * The hash object's incoming x0 is unused; event arrives in x1. */
uint64_t mobilelogic_macore_event_diff_hash_method(const void *hash_object,
                                                  const void *event) {
  (void)hash_object;
  return mobilelogic_macore_event_diff_hash(event);
}

/* Original 0xa918..0xa95c, unnamed field-packing hash.
 * The SIMD mask selects input bytes 0,1,4; two 32-bit shifts then
 * discard bytes 9..11 and 14..15, respectively. Untouched input bytes
 * have no effect. Avoid signed shift/overflow and unaligned C loads. */
uint64_t mobilelogic_macore_field_hash_a918(const void *fields) {
  const unsigned char *p = fields;
  return (uint64_t)p[16] | ((uint64_t)p[17] << 8) |
         ((uint64_t)p[12] << 16) | ((uint64_t)p[13] << 24) |
         ((uint64_t)p[0] << 32) | ((uint64_t)p[1] << 40) |
         ((uint64_t)p[4] << 48) | ((uint64_t)p[8] << 56);
}
