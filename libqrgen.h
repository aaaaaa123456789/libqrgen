#ifndef ___LIB_QRGEN

#define ___LIB_QRGEN 1

#include <limits.h>

#if CHAR_BIT != 8
  #error This library requires 8-bit chars. Please ensure the target platform uses chars of this width and try again.
#endif

#define QR_PIXELS_PER_SIDE(version) (17 + ((version) << 2))
#define QR_BYTES_PER_ROW(version) ((QR_PIXELS_PER_SIDE(version) >> 3) + 1)
#define QR_BUFFER_SIZE(version) (QR_PIXELS_PER_SIDE(version) * QR_BYTES_PER_ROW(version))

#ifdef __cplusplus
  extern "C" {
#endif

unsigned char generate_QR_code(const void * data, unsigned short length, unsigned char target_version, unsigned char limit_version, void * buffer);

#ifdef __cplusplus
  }
#endif

#endif
