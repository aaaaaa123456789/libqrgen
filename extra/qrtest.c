#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libqrgen.h"

const unsigned char BMP_header[] = {
  0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x28, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00
};

int emit_BMP_header (FILE * file, unsigned char size) {
  unsigned char header[sizeof BMP_header];
  memcpy(header, BMP_header, sizeof header);
  unsigned data_size = size * (size >> 5);
  data_size = (data_size << 2) + 0x3E;
  header[2] = data_size;
  header[3] = data_size >> 8;
  header[18] = header[22] = size;
  return fwrite(header, 1, sizeof header, file) == sizeof header;
}

void emit_QR_data (FILE * file, const unsigned char * data, unsigned char version) {
  unsigned char full_bytes = QR_BYTES_PER_ROW(version) - 1;
  unsigned char mask = -(1 << (8 - (QR_PIXELS_PER_SIDE(version) & 7)));
  unsigned char extra_bytes = 4 - (QR_BYTES_PER_ROW(version) & 3);
  unsigned char row, col, value;
  for (row = full_bytes + extra_bytes + 1; row; row --) for (col = 0; col < 4; col ++) putc(0, file);
  row = QR_PIXELS_PER_SIDE(version);
  const unsigned char * row_data;
  do {
    row --;
    value = 0;
    row_data = data + row * QR_BYTES_PER_ROW(version);
    for (col = 0; col < full_bytes; col ++) {
      value |= *row_data >> 4;
      putc(value, file);
      value = *(row_data ++) << 4;
    }
    col = *(row_data ++) & mask;
    value |= col >> 4;
    putc(value, file);
    value = col << 4;
    for (col = 0; col < extra_bytes; col ++) {
      putc(value, file);
      value = 0;
    }
  } while (row);
  for (row = full_bytes + extra_bytes + 1; row; row --) for (col = 0; col < 4; col ++) putc(0, file);
}

unsigned char get_version_number (const char * string) {
  long long value = strtoll(string, NULL, 10);
  if ((value < 1) || (value > 40)) return 0;
  return value;
}

int main (int argc, char ** argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <target version> <limit version> <data>\n", *argv);
    return 1;
  }
  unsigned char target, limit;
  target = get_version_number(argv[1]);
  limit = get_version_number(argv[2]);
  if (!(target && limit)) {
    fputs("error: version numbers must be between 1 and 40\n", stderr);
    return 2;
  }
  unsigned char version = (target > limit) ? target : limit;
  void * buffer = malloc(QR_BUFFER_SIZE(version));
  version = generate_QR_code(argv[3], strlen(argv[3]), target, limit, buffer);
  if (!version) {
    free(buffer);
    fputs("error: could not generate QR code\n", stderr);
    return 3;
  }
  emit_BMP_header(stdout, QR_PIXELS_PER_SIDE(version) + 8);
  emit_QR_data(stdout, buffer, version);
  free(buffer);
  return 0;
}
