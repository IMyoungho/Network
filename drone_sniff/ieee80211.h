#ifndef IEEE80211_H
#define IEEE80211_H
#include <stdint.h>

struct radiotap_header
{
    uint8_t  header_revision;
    uint8_t  header_pad;
    uint16_t header_length;
    uint8_t  present_flags[8];
/*Present flags word

    uint32_t tsft:1;
    uint32_t flags:1;
    uint32_t rate:1;
    uint32_t channel:1;
    uint32_t fhss:1;
    uint32_t dbm_ant_siganl:1;
    uint32_t dbm_ant_noise:1;
    uint32_t lock_quality:1;
    uint32_t tx_attenuation:1;
    uint32_t db_tx_attenuation:1;
    uint32_t dbm_tx_Power:1;
    uint32_t antenna_flag:1;
    uint32_t db_ant_signal:1;
    uint32_t db_ant_noise:1;
    uint32_t rxflags:1;
    uint32_t p_flags_padding:3;
    uint32_t channel_plus:1;
    uint32_t mcs_info:1;
    uint32_t a_mpdu_status:1;
    uint32_t vht_info:1;
    uint32_t reserved:7;
    uint32_t radio_ns:1;
    uint32_t vendor_ns:1;
    uint32_t ext:1;

    //Present flags word
    uint32_t tsft:1;
    uint32_t flags:1;
    uint32_t rate:1;
    uint32_t channel:1;
    uint32_t fhss:1;
    uint32_t dbm_ant_siganl:1;
    uint32_t dbm_ant_noise:1;
    uint32_t lock_quality:1;
    uint32_t tx_attenuation:1;
    uint32_t db_tx_attenuation:1;
    uint32_t dbm_tx_Power:1;
    uint32_t antenna_flag:1;
    uint32_t db_ant_signal:1;
    uint32_t db_ant_noise:1;
    uint32_t rxflags:1;
    uint32_t p_flags_padding:3;
    uint32_t channel_plus:1;
    uint32_t mcs_info:1;
    uint32_t a_mpdu_status:1;
    uint32_t vht_info:1;
    uint32_t reserved:7;
    uint32_t radio_ns:1;
    uint32_t vendor_ns:1;
    uint32_t ext:1;
    */
    uint64_t mac_timestamp;
//flags
    uint8_t  cfp:1;
    uint8_t  preamble:1;
    uint8_t  wep:1;
    uint8_t  fragementation:1;
    uint8_t  fcs:1;
    uint8_t  data_pad:1;
    uint8_t  bad_fcs:1;
    uint8_t  short_gi:1;

    uint8_t  data_rate;
    uint16_t channel_frequency;

//Channel_flags;
    uint16_t ch_padding:4;
    uint16_t turbo:1;
    uint16_t complementary_code_keying:1;
    uint16_t orthogonal_freq:1;
    uint16_t ghz_2:1;
    uint16_t ghz_5:1;
    uint16_t passive:1;
    uint16_t dynamic_cck:1;
    uint16_t gaussian_freq:1;
    uint16_t gsm:1;
    uint16_t static_turbo:1;
    uint16_t half_rate_channel:1;
    uint16_t quarter_rate_channel:1;

    uint8_t  ssi_signal;
    uint8_t  antenna;
    uint16_t rx_flags;
};
struct ieee80211_common
{
/*Frame Control Field
    uint8_t version:2;
    uint8_t type:2;
    uint8_t sutype:4;
    */
    uint8_t frame_control_field;
//flags
    uint8_t ds:2;
    uint8_t more:1;
    uint8_t retry:1;
    uint8_t pwr:1;
    uint8_t more2:1;
    uint8_t protect:1;
    uint8_t order:1;

    uint16_t duration;
};
struct ieee80211_qos_frame{
    uint8_t sta[6];
    uint8_t bssid[6];
    uint8_t src[6];
    uint16_t fragment_num:4;
    uint16_t sequence_num:12;
    uint16_t qos_control;
};

#endif // IEEE80211_H
