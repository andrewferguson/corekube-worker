#include "s1ap_conv.h"
#include "s1ap/asn1c/asn_SEQUENCE_OF.h"
#include "core/include/3gpp_types.h" // for MAX_SDU_LEN

// Some of these functions are taken from, or heavily
// inspired by, the functions in nextepc/src/mme/s1ap_conv.c

void s1ap_uint8_to_OCTET_STRING(c_uint8_t uint8, OCTET_STRING_t *octet_string)
{
    octet_string->size = 1;
    octet_string->buf = core_calloc(octet_string->size, sizeof(c_uint8_t));

    octet_string->buf[0] = uint8;
}

void s1ap_uint16_to_OCTET_STRING(c_uint16_t uint16, OCTET_STRING_t *octet_string)
{
    octet_string->size = 2;
    octet_string->buf = core_calloc(octet_string->size, sizeof(c_uint8_t));

    octet_string->buf[0] = (uint16 >> 8) & 0xFF;
    octet_string->buf[1] = (uint16) & 0xFF;
}

void s1ap_uint32_to_OCTET_STRING(c_uint32_t uint32, OCTET_STRING_t *octet_string)
{
    octet_string->size = 4;
    octet_string->buf = core_calloc(octet_string->size, sizeof(c_uint8_t));

    octet_string->buf[0] = (uint32 >> 24) & 0xFF;
    octet_string->buf[1] = (uint32 >> 16) & 0xFF;
    octet_string->buf[2] = (uint32 >> 8) & 0xFF;
    octet_string->buf[3] = (uint32) & 0xFF;
}

void s1ap_buffer_to_OCTET_STRING(
        void *buf, int size, S1AP_TBCD_STRING_t *tbcd_string)
{
    tbcd_string->size = size;
    tbcd_string->buf = core_calloc(tbcd_string->size, sizeof(c_uint8_t));

    memcpy(tbcd_string->buf, buf, size);
}

void s1ap_ENB_ID_to_uint32(S1AP_ENB_ID_t *eNB_ID, c_uint32_t *uint32)
{
    d_assert(uint32, return, "Null param");
    d_assert(eNB_ID, return, "Null param");

    if (eNB_ID->present == S1AP_ENB_ID_PR_homeENB_ID)
    {
        c_uint8_t *buf = eNB_ID->choice.homeENB_ID.buf;
        d_assert(buf, return, "Null param");
        *uint32 = (buf[0] << 20) + (buf[1] << 12) + (buf[2] << 4) +
            ((buf[3] & 0xf0) >> 4);

    }
    else if (eNB_ID->present == S1AP_ENB_ID_PR_macroENB_ID)
    {
        c_uint8_t *buf = eNB_ID->choice.macroENB_ID.buf;
        d_assert(buf, return, "Null param");
        *uint32 = (buf[0] << 12) + (buf[1] << 4) + ((buf[2] & 0xf0) >> 4);
    }
    else
    {
        d_assert(0, return, "Invalid param");
    }
}

status_t s1ap_copy_ie(const asn_TYPE_descriptor_t *td, void *src, void *dst)
{
    asn_enc_rval_t enc_ret = {0};
    asn_dec_rval_t dec_ret = {0};
    c_uint8_t buffer[MAX_SDU_LEN];

    d_assert(td, return CORE_ERROR,);
    d_assert(src, return CORE_ERROR,);
    d_assert(dst, return CORE_ERROR,);

    enc_ret = aper_encode_to_buffer(td, NULL, src, buffer, MAX_SDU_LEN);
    if (enc_ret.encoded < 0)
    {
        d_error("aper_encode_to_buffer() failed[%d]", enc_ret.encoded);
        return CORE_ERROR;
    }

    dec_ret = aper_decode(NULL, td, (void **)&dst,
            buffer, (enc_ret.encoded >> 3), 0, 0);

    if (dec_ret.code != RC_OK)
    {
        d_error("aper_decode() failed[%d]", dec_ret.code);
        return CORE_ERROR;
    }

    return CORE_OK;
}

int array_to_int(uint8_t * buffer)
{
	return (int)((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]);
}