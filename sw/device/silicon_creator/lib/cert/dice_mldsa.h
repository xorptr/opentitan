#include "sw/device/lib/base/macros.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/keymgr.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/keymgr_binding_value.h"

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
