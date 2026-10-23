/* Logic.framework application-recording option accessors.
 *
 * Original entries:
 *   0xd1243c / 0xd12448  audio-cycle get/set
 *   0xd12454 / 0xd12460  audio-no-cycle get/set
 *
 * The original values are signed 16-bit module globals.  Symbol placement is
 * a link-layout concern; the source contract is the two shared objects and
 * four actual entry ABIs, not their original virtual addresses.
 */
#include <stdint.h>

volatile int16_t mobilelogic_recording_options_audio_cycle = 0;
volatile int16_t mobilelogic_recording_options_audio_no_cycle = 0;

int32_t mobilelogic_recording_options_audio_cycle_get(void) {
  return mobilelogic_recording_options_audio_cycle;
}

void mobilelogic_recording_options_audio_cycle_set(int32_t value) {
  mobilelogic_recording_options_audio_cycle = (int16_t)value;
}

int32_t mobilelogic_recording_options_audio_no_cycle_get(void) {
  return mobilelogic_recording_options_audio_no_cycle;
}

void mobilelogic_recording_options_audio_no_cycle_set(int32_t value) {
  mobilelogic_recording_options_audio_no_cycle = (int16_t)value;
}
