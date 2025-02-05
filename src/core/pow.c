#include
#include
#include
#include
#include

#include

#include "common/util.h"
#include "common/logger.h"

#include "pow.h"

#include "crypto/bignum_util.h"
#include "crypto/cryptoutil.h"

static const char *g_pow_limit_str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
BIGNUM *g_pow_limit_bn = NULL;

int init_pow(void)
{
  if (g_pow_limit_bn != NULL)
  {
    LOG_WARN("Proof-of-work already initialized.");
    return 1;
  }

  size_t out_size = 0;
  uint8_t *pow_limit_bin = hex2bin(g_pow_limit_str, &out_size);
  if (out_size != HASH_SIZE)
  {
    LOG_ERROR("Hex to binary conversion size mismatch.");
    free(pow_limit_bin);
    return 1;
  }

  g_pow_limit_bn = BN_new();
  if (g_pow_limit_bn == NULL)
  {
    LOG_ERROR("Failed to allocate BIGNUM for POW limit.");
    free(pow_limit_bin);
    return 1;
  }

  if (BN_bin2bn(pow_limit_bin, HASH_SIZE, g_pow_limit_bn) == NULL)
  {
    LOG_ERROR("Failed to convert binary to BIGNUM for POW limit.");
    BN_free(g_pow_limit_bn);
    g_pow_limit_bn = NULL;
    free(pow_limit_bin);
    return 1;
  }

  if (BN_is_zero(g_pow_limit_bn))
  {
    LOG_ERROR("POW limit BIGNUM is zero.");
    BN_clear_free(g_pow_limit_bn);
    g_pow_limit_bn = NULL;
    free(pow_limit_bin);
    return 1;
  }

  free(pow_limit_bin);
  return 0;
}

int deinit_pow(void)
{
  if (g_pow_limit_bn == NULL)
  {
    LOG_WARN("Proof-of-work not initialized.");
    return 1;
  }

  // Clear and free the BIGNUM to securely remove it from memory
  BN_clear_free(g_pow_limit_bn);
  g_pow_limit_bn = NULL;
  return 0;
}

int check_proof_of_work(const uint8_t *hash, uint32_t bits)
{
  if (g_pow_limit_bn == NULL)
  {
    LOG_ERROR("Proof-of-work not initialized.");
    return 0;
  }

  if (BN_is_zero(g_pow_limit_bn))
  {
    LOG_ERROR("POW limit BIGNUM is zero.");
    return 0;
  }

  BIGNUM *bn_target = BN_new();
  BIGNUM *hash_target = BN_new();

  if (bn_target == NULL || hash_target == NULL)
  {
    LOG_ERROR("Failed to allocate BIGNUM for target or hash.");
    BN_free(bn_target);
    BN_free(hash_target);
    return 0;
  }

  bignum_set_compact(bn_target, bits);
  if (BN_bin2bn(hash, HASH_SIZE, hash_target) == NULL)
  {
    LOG_ERROR("Failed to convert hash to BIGNUM.");
    BN_clear_free(bn_target);
    BN_free(hash_target);
    return 0;
  }

  // Check range
  if (BN_is_zero(bn_target) || BN_cmp(bn_target, g_pow_limit_bn) == 1)
  {
    LOG_WARN("Invalid target difficulty.");
    goto pow_check_fail;
  }

  // Check proof of work
  if (BN_cmp(hash_target, bn_target) == 1)
  {
    LOG_DEBUG("Hash does not meet proof-of-work requirement.");
    goto pow_check_fail;
  }

  BN_clear_free(bn_target);
  BN_clear_free(hash_target);
  return 1;

pow_check_fail:
  BN_clear_free(bn_target);
  BN_clear_free(hash_target);
  return 0;
}
