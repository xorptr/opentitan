#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/macros.h"
#include "sw/device/silicon_creator/lib/cert/dice_keys.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/keymgr.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/keymgr_binding_value.h"
#include "sw/device/silicon_creator/lib/sigverify/mldsa_key.h"

// Keymgr configurations for deriving attestation keys.
typedef struct keygen_params {
  const sc_keymgr_ecc_key_t *ecc_cfg;
  const sc_keymgr_ecc_key_t *mldsa_cfg;
} keygen_params_t;

extern const keygen_params_t kUdsKeygenParams;

/**
 * Derives a 256-bit ML-DSA private key seed using the SP800-133r3 scheme.
 *
 * @param params Key generation parameters.
 * @param[out] seed_output Derived 256-bit ML-DSA key seed.
 */
OT_WARN_UNUSED_RESULT rom_error_t dice_mldsa_derive_seed(
    const keygen_params_t *params, keymgr_binding_value_t *seed_output);

/**
 * Derives a 256-bit ML-DSA certificate ID from a seed.
 *
 * @param seed The ML-DSA key seed.
 * @param[out] id The computed public key ID.
 */
void get_mldsa_id(const hmac_key_t *seed, hmac_digest_t *id);

OT_WARN_UNUSED_RESULT
rom_error_t dice_uds_mldsa_tbs_cert_build(
    const hmac_digest_t *otp_creator_sw_cfg_measurement,
    const hmac_digest_t *otp_owner_sw_cfg_measurement,
    const hmac_digest_t *otp_rot_creator_auth_codesign_measurement,
    const hmac_digest_t *otp_rot_creator_auth_state_measurement,
    const cert_key_id_pair_t *key_ids, const mldsa_public_key_t *uds_pubkey,
    uint8_t *tbs_cert, size_t *tbs_cert_size);
