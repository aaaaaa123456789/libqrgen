#include <stdlib.h>
#include <string.h>

#include "libqrgen.h"

struct qrgen_ECC_parameters {
  // should fit in a CPU register (assuming that nobody's using 16-bit CPUs these days)
  unsigned blocks:       8;
  unsigned short_blocks: 8;
  unsigned data_bytes:   8; // in long blocks; short blocks have one fewer byte
  unsigned ECC_bytes:    8;
};

enum qrgen_QR_module_values {
  QRGEN_WHITE = 0,
  QRGEN_BLACK = 1,
  QRGEN_RESERVED = 2,
  QRGEN_BLACK_NONMASKED = 3,
  QRGEN_WHITE_NONMASKED = 4,
  QRGEN_BLACK_WITHMASK = 5,
  QRGEN_WHITE_WITHMASK = 6,
  QRGEN_EMPTY = 255
};

#define QRGEN_MASKING_OFFSET 5

static unsigned short qrgen_encode_data(unsigned char *, const unsigned char *, unsigned short, unsigned char);
static unsigned char qrgen_select_parameters(const unsigned short *, unsigned char, unsigned char, int);
static unsigned char qrgen_select_parameters_for_kind(unsigned short, unsigned char, unsigned char, int);
static unsigned char qrgen_minimum_version_for_parameters(unsigned short, unsigned char, unsigned char, unsigned char);
static unsigned short qrgen_maximum_data_length(unsigned char, unsigned char);
static unsigned short qrgen_data_bits_for_version(unsigned char);
static unsigned char qrgen_alignment_pattern_count(unsigned char);
static unsigned char qrgen_alignment_pattern_position(unsigned char, unsigned char);
static int qrgen_generate_QR(const unsigned char *, unsigned short, unsigned char, unsigned char, unsigned char *);
static int qrgen_encode_QR_data(const unsigned char *, unsigned short, unsigned char, unsigned char, unsigned char *);
static struct qrgen_ECC_parameters qrgen_calculate_ECC_parameters(unsigned char, unsigned char);
static void qrgen_generate_ECC_stream(const unsigned char *, unsigned char *, struct qrgen_ECC_parameters);
static void qrgen_generate_ECC_data(const unsigned char *, unsigned char, unsigned char *, unsigned char);
static void qrgen_generate_ECC_polynomial(unsigned char, unsigned char *);
static unsigned char qrgen_ECC_multiply(unsigned char, unsigned char);
static void qrgen_interleave(const unsigned char *, const unsigned char *, struct qrgen_ECC_parameters, unsigned char *);
static int qrgen_build_QR(const unsigned char *, unsigned char, unsigned char, unsigned char *);
static void qrgen_place_function_patterns(unsigned char *, unsigned char, unsigned char);
static void qrgen_place_position_identification_pattern(unsigned char *, unsigned char, unsigned char, unsigned char);
static void qrgen_place_alignment_patterns(unsigned char *, unsigned char, unsigned char);
static unsigned qrgen_compute_polynomial_error_correction(unsigned, unsigned, unsigned char);
static void qrgen_place_version_information(unsigned char *, unsigned char, unsigned char);
static void qrgen_place_format_information(unsigned char *, unsigned char, short);
static unsigned short qrgen_compute_format_information(unsigned char, unsigned char);
static void qrgen_place_data_modules(unsigned char *, unsigned char, unsigned char, const unsigned char *);
static unsigned short qrgen_scan_index(unsigned short, unsigned char);
static unsigned char qrgen_select_masking(unsigned char *, unsigned char, unsigned char);
static void qrgen_apply_masking(unsigned char *, unsigned char, unsigned char, unsigned char);
static unsigned qrgen_compute_masking_score(unsigned char *, unsigned char, unsigned char);
static void qrgen_unmask(unsigned char *, unsigned char);
static void qrgen_export_QR_data(const unsigned char *, unsigned char, unsigned char *);

// anything going over this limit just doesn't fit; fail and exit
#define QRGEN_ENCODING_BUFFER_SIZE 4096

#define QRGEN_PARAMS(blocks, ECC_bytes) ((((blocks) & 0xFF) << 8) | ((ECC_bytes) & 0xFF))

static const unsigned short qrgen_error_correction_parameters[] = {
  // one value per version and ECC combination, stating the number of blocks and the ECC bytes per block
  // ECC:         low                medium               quarter                  high
  QRGEN_PARAMS( 1,  7), QRGEN_PARAMS( 1, 10), QRGEN_PARAMS( 1, 13), QRGEN_PARAMS( 1, 17), //  1
  QRGEN_PARAMS( 1, 10), QRGEN_PARAMS( 1, 16), QRGEN_PARAMS( 1, 22), QRGEN_PARAMS( 1, 28), //  2
  QRGEN_PARAMS( 1, 15), QRGEN_PARAMS( 1, 26), QRGEN_PARAMS( 2, 18), QRGEN_PARAMS( 2, 22), //  3
  QRGEN_PARAMS( 1, 20), QRGEN_PARAMS( 2, 18), QRGEN_PARAMS( 2, 26), QRGEN_PARAMS( 4, 16), //  4
  QRGEN_PARAMS( 1, 26), QRGEN_PARAMS( 2, 24), QRGEN_PARAMS( 4, 18), QRGEN_PARAMS( 4, 22), //  5
  QRGEN_PARAMS( 2, 18), QRGEN_PARAMS( 4, 16), QRGEN_PARAMS( 4, 24), QRGEN_PARAMS( 4, 28), //  6
  QRGEN_PARAMS( 2, 20), QRGEN_PARAMS( 4, 18), QRGEN_PARAMS( 6, 18), QRGEN_PARAMS( 5, 26), //  7
  QRGEN_PARAMS( 2, 24), QRGEN_PARAMS( 4, 22), QRGEN_PARAMS( 6, 22), QRGEN_PARAMS( 6, 26), //  8
  QRGEN_PARAMS( 2, 30), QRGEN_PARAMS( 5, 22), QRGEN_PARAMS( 8, 20), QRGEN_PARAMS( 8, 24), //  9
  QRGEN_PARAMS( 4, 18), QRGEN_PARAMS( 5, 26), QRGEN_PARAMS( 8, 24), QRGEN_PARAMS( 8, 28), // 10
  QRGEN_PARAMS( 4, 20), QRGEN_PARAMS( 5, 30), QRGEN_PARAMS( 8, 28), QRGEN_PARAMS(11, 24), // 11
  QRGEN_PARAMS( 4, 24), QRGEN_PARAMS( 8, 22), QRGEN_PARAMS(10, 26), QRGEN_PARAMS(11, 28), // 12
  QRGEN_PARAMS( 4, 26), QRGEN_PARAMS( 9, 22), QRGEN_PARAMS(12, 24), QRGEN_PARAMS(16, 22), // 13
  QRGEN_PARAMS( 4, 30), QRGEN_PARAMS( 9, 24), QRGEN_PARAMS(16, 20), QRGEN_PARAMS(16, 24), // 14
  QRGEN_PARAMS( 6, 22), QRGEN_PARAMS(10, 24), QRGEN_PARAMS(12, 30), QRGEN_PARAMS(18, 24), // 15
  QRGEN_PARAMS( 6, 24), QRGEN_PARAMS(10, 28), QRGEN_PARAMS(17, 24), QRGEN_PARAMS(16, 30), // 16
  QRGEN_PARAMS( 6, 28), QRGEN_PARAMS(11, 28), QRGEN_PARAMS(16, 28), QRGEN_PARAMS(19, 28), // 17
  QRGEN_PARAMS( 6, 30), QRGEN_PARAMS(13, 26), QRGEN_PARAMS(18, 28), QRGEN_PARAMS(21, 28), // 18
  QRGEN_PARAMS( 7, 28), QRGEN_PARAMS(14, 26), QRGEN_PARAMS(21, 26), QRGEN_PARAMS(25, 26), // 19
  QRGEN_PARAMS( 8, 28), QRGEN_PARAMS(16, 26), QRGEN_PARAMS(20, 30), QRGEN_PARAMS(25, 28), // 20
  QRGEN_PARAMS( 8, 28), QRGEN_PARAMS(17, 26), QRGEN_PARAMS(23, 28), QRGEN_PARAMS(25, 30), // 21
  QRGEN_PARAMS( 9, 28), QRGEN_PARAMS(17, 28), QRGEN_PARAMS(23, 30), QRGEN_PARAMS(34, 26), // 22
  QRGEN_PARAMS( 9, 30), QRGEN_PARAMS(18, 28), QRGEN_PARAMS(25, 30), QRGEN_PARAMS(30, 30), // 23
  QRGEN_PARAMS(10, 30), QRGEN_PARAMS(20, 28), QRGEN_PARAMS(27, 30), QRGEN_PARAMS(32, 30), // 24
  QRGEN_PARAMS(12, 26), QRGEN_PARAMS(21, 28), QRGEN_PARAMS(29, 30), QRGEN_PARAMS(35, 30), // 25
  QRGEN_PARAMS(12, 28), QRGEN_PARAMS(23, 28), QRGEN_PARAMS(34, 28), QRGEN_PARAMS(37, 30), // 26
  QRGEN_PARAMS(12, 30), QRGEN_PARAMS(25, 28), QRGEN_PARAMS(34, 30), QRGEN_PARAMS(40, 30), // 27
  QRGEN_PARAMS(13, 30), QRGEN_PARAMS(26, 28), QRGEN_PARAMS(35, 30), QRGEN_PARAMS(42, 30), // 28
  QRGEN_PARAMS(14, 30), QRGEN_PARAMS(28, 28), QRGEN_PARAMS(38, 30), QRGEN_PARAMS(45, 30), // 29
  QRGEN_PARAMS(15, 30), QRGEN_PARAMS(29, 28), QRGEN_PARAMS(40, 30), QRGEN_PARAMS(48, 30), // 30
  QRGEN_PARAMS(16, 30), QRGEN_PARAMS(31, 28), QRGEN_PARAMS(43, 30), QRGEN_PARAMS(51, 30), // 31
  QRGEN_PARAMS(17, 30), QRGEN_PARAMS(33, 28), QRGEN_PARAMS(45, 30), QRGEN_PARAMS(54, 30), // 32
  QRGEN_PARAMS(18, 30), QRGEN_PARAMS(35, 28), QRGEN_PARAMS(48, 30), QRGEN_PARAMS(57, 30), // 33
  QRGEN_PARAMS(19, 30), QRGEN_PARAMS(37, 28), QRGEN_PARAMS(51, 30), QRGEN_PARAMS(60, 30), // 34
  QRGEN_PARAMS(19, 30), QRGEN_PARAMS(38, 28), QRGEN_PARAMS(53, 30), QRGEN_PARAMS(63, 30), // 35
  QRGEN_PARAMS(20, 30), QRGEN_PARAMS(40, 28), QRGEN_PARAMS(56, 30), QRGEN_PARAMS(66, 30), // 36
  QRGEN_PARAMS(21, 30), QRGEN_PARAMS(43, 28), QRGEN_PARAMS(59, 30), QRGEN_PARAMS(70, 30), // 37
  QRGEN_PARAMS(22, 30), QRGEN_PARAMS(45, 28), QRGEN_PARAMS(62, 30), QRGEN_PARAMS(74, 30), // 38
  QRGEN_PARAMS(24, 30), QRGEN_PARAMS(47, 28), QRGEN_PARAMS(65, 30), QRGEN_PARAMS(77, 30), // 39
  QRGEN_PARAMS(25, 30), QRGEN_PARAMS(49, 28), QRGEN_PARAMS(68, 30), QRGEN_PARAMS(81, 30)  // 40
};

unsigned char generate_QR_code (const void * data, unsigned short length, unsigned char target_version, unsigned char limit_version, void * buffer) {
  if ((target_version < 1) || (target_version > 40) || (limit_version < 1) || (limit_version > 40)) return 0;
  if (length && !data) return 0;
  unsigned char encoding_buffer[QRGEN_ENCODING_BUFFER_SIZE * 3];
  unsigned short lengths[3] = {0, 0, 0};
  // only encode the kinds we care about
  if ((target_version < 10) || (limit_version < 10))
    *lengths = qrgen_encode_data(encoding_buffer, data, length, 0);
  if (((target_version > 9) || (limit_version > 9)) && ((target_version < 27) || (limit_version < 27)))
    lengths[1] = qrgen_encode_data(encoding_buffer + QRGEN_ENCODING_BUFFER_SIZE, data, length, 1);
  if ((target_version > 26) || (limit_version > 26))
    lengths[2] = qrgen_encode_data(encoding_buffer + QRGEN_ENCODING_BUFFER_SIZE * 2, data, length, 2);
  unsigned char version;
  if (target_version < limit_version)
    version = qrgen_select_parameters(lengths, target_version, limit_version, 0);
  else
    version = qrgen_select_parameters(lengths, limit_version, target_version, 1);
  if (!version) return 0;
  unsigned char ECC = version & 3;
  version >>= 2;
  int rv = qrgen_generate_QR(encoding_buffer + QRGEN_ENCODING_BUFFER_SIZE * ((version > 9) + (version > 26)),
                             lengths[(version > 9) + (version > 26)], version, ECC, buffer);
  if (rv) return 0;
  return version;
}

static unsigned short qrgen_encode_data (unsigned char * buffer, const unsigned char * data, unsigned short length, unsigned char kind) {
  // for now we don't attempt anything fancy; just encode it as binary 8-bit data... boring
  if (length >= (QRGEN_ENCODING_BUFFER_SIZE - 3)) return 0;
  unsigned char * wp = buffer;
  if (!kind && (length > 255)) return 0;
  if (kind) {
    *(wp ++) = 0x40 | (length >> 12);
    *(wp ++) = length >> 4;
  } else
    *(wp ++) = 0x40 | (length >> 4);
  *wp = length << 4;
  while (length --) {
    *(wp ++) |= *data >> 4;
    *wp = *(data ++) << 4;
  }
  return (wp + 1) - buffer;
}

static unsigned char qrgen_select_parameters (const unsigned short * lengths, unsigned char min_version, unsigned char max_version, int maximize_ECC) {
  // bits 7-2: version, 1-0: ECC; 0 means no suitable version
  unsigned char small = 0, medium = 0, large = 0;
  if (min_version < 10)
    small = qrgen_select_parameters_for_kind(*lengths, min_version, (max_version > 9) ? 9 : max_version, maximize_ECC);
  if ((min_version < 27) && (max_version > 9))
    medium = qrgen_select_parameters_for_kind(lengths[1], (min_version < 10) ? 10 : min_version, (max_version > 26) ? 26 : max_version, maximize_ECC);
  if (max_version > 26)
    large = qrgen_select_parameters_for_kind(lengths[2], (min_version < 27) ? 27 : min_version, max_version, maximize_ECC);
  unsigned char result = small;
  if (!result || (maximize_ECC && ((medium & 3) > (result & 3)))) result = medium;
  if (!result || (maximize_ECC && ((large & 3) > (result & 3)))) result = large;
  return result;
}

static unsigned char qrgen_select_parameters_for_kind (unsigned short length, unsigned char min_version, unsigned char max_version, int maximize_ECC) {
  unsigned char version, ECC;
  if (maximize_ECC) {
    for (ECC = 3; ECC <= 3; ECC --) {
      version = qrgen_minimum_version_for_parameters(length, min_version, max_version, ECC);
      if (version) break;
    }
    if (ECC > 3) return 0;
  } else {
    version = qrgen_minimum_version_for_parameters(length, min_version, max_version, 0);
    if (!version) return 0;
    for (ECC = 0; ECC < 3; ECC ++) if (qrgen_maximum_data_length(version, ECC + 1) < length) break;
  }
  return (version << 2) | ECC;
}

static unsigned char qrgen_minimum_version_for_parameters (unsigned short length, unsigned char min_version, unsigned char max_version, unsigned char ECC) {
  unsigned char version;
  for (version = min_version; version <= max_version; version ++)
    if (length <= qrgen_maximum_data_length(version, ECC)) return version;
  return 0;
}

static unsigned short qrgen_maximum_data_length (unsigned char version, unsigned char ECC) {
  unsigned short bits = qrgen_data_bits_for_version(version);
  unsigned short parameters = qrgen_error_correction_parameters[(version - 1) * 4 + ECC];
  return (bits >> 3) - (parameters >> 8) * (parameters & 0xFF);
}

static unsigned short qrgen_data_bits_for_version (unsigned char version) {
  unsigned size = version * 4 + 17;
  size *= size;
  size -= 225; // position detection patterns, separation and format information
  size -= 8 * version; // timing patterns
  size -= 25 * qrgen_alignment_pattern_count(version); // alignment patterns
  size += 10 * (version / 7); // add back the overlap between timing and alignment patterns
  if (version >= 7) size -= 36; // account for version information if needed
  return size;
}

static unsigned char qrgen_alignment_pattern_count (unsigned char version) {
  if (version < 2) return 0;
  unsigned char side = version / 7 + 2;
  return side * side - 3;
}

static unsigned char qrgen_alignment_pattern_position (unsigned char version, unsigned char index) {
  if (version < 2) return -1;
  unsigned char num_steps = version / 7 + 1;
  if (index > num_steps) return -1;
  if (!index) return 6;
  unsigned char max = version * 4 + 10;
  unsigned char step = ((max - 6) * 2 / num_steps + 1) / 2; // (max - 6) / num_steps, rounded to nearest
  if (step & 1) step ++;
  return max - step * (num_steps - index);
}

static int qrgen_generate_QR (const unsigned char * data, unsigned short length, unsigned char version, unsigned char ECC, unsigned char * result) {
  // returns 0 on success
  unsigned char buffer[QRGEN_ENCODING_BUFFER_SIZE];
  if (length > QRGEN_ENCODING_BUFFER_SIZE) return 1;
  int rv = qrgen_encode_QR_data(data, length, version, ECC, buffer);
  if (rv) return rv;
  return qrgen_build_QR(buffer, version, ECC, result);
}

static int qrgen_encode_QR_data (const unsigned char * data, unsigned short length, unsigned char version, unsigned char ECC, unsigned char * buffer) {
  unsigned char data_stream[QRGEN_ENCODING_BUFFER_SIZE];
  unsigned char ECC_stream[QRGEN_ENCODING_BUFFER_SIZE];
  unsigned short limit = qrgen_maximum_data_length(version, ECC);
  if (length > limit) return 2;
  memcpy(data_stream, data, length);
  unsigned char filler = 0xEC;
  unsigned short position;
  for (position = length; position < limit; position ++) {
    data_stream[position] = filler;
    filler ^= 0xFD; // alternates between 0xEC and 0x11
  }
  struct qrgen_ECC_parameters parameters = qrgen_calculate_ECC_parameters(version, ECC);
  qrgen_generate_ECC_stream(data_stream, ECC_stream, parameters);
  qrgen_interleave(data_stream, ECC_stream, parameters, buffer);
  return 0;
}

static struct qrgen_ECC_parameters qrgen_calculate_ECC_parameters (unsigned char version, unsigned char ECC) {
  struct qrgen_ECC_parameters parameters;
  unsigned short p = qrgen_error_correction_parameters[(version - 1) * 4 + ECC];
  unsigned data_length = qrgen_maximum_data_length(version, ECC);
  parameters.blocks = p >> 8;
  parameters.ECC_bytes = p & 0xFF;
  parameters.data_bytes = data_length / parameters.blocks;
  if (data_length % parameters.blocks) {
    parameters.data_bytes ++;
    parameters.short_blocks = parameters.blocks - (data_length % parameters.blocks);
  } else
    parameters.short_blocks = 0;
  return parameters;
}

static void qrgen_generate_ECC_stream (const unsigned char * data, unsigned char * output, struct qrgen_ECC_parameters parameters) {
  unsigned block, length;
  for (block = 0; block < parameters.blocks; block ++) {
    length = parameters.data_bytes - (block < parameters.short_blocks);
    qrgen_generate_ECC_data(data, length, output, parameters.ECC_bytes);
    data += length;
    output += parameters.ECC_bytes;
  }
}

static void qrgen_generate_ECC_data (const unsigned char * data, unsigned char length, unsigned char * output, unsigned char output_length) {
  unsigned char polynomial[32]; // 32 is longer than any valid ECC length, and it keeps the array nicely aligned to cache lines
  memset(output, 0, output_length);
  qrgen_generate_ECC_polynomial(output_length, polynomial);
  unsigned char pos, index, input;
  for (pos = 0; pos < length; pos ++) {
    input = data[pos] ^ *output;
    for (index = 0; index < (output_length - 1); index ++)
      output[index] = output[index + 1] ^ qrgen_ECC_multiply(input, polynomial[output_length - 1 - index]);
    output[output_length - 1] = qrgen_ECC_multiply(input, *polynomial);
  }
}

static void qrgen_generate_ECC_polynomial (unsigned char degree, unsigned char * output) {
  // result = product of (x - 2^n) for n = 0 to degree - 1; -k = k in GF(2^n)
  *output = 1; // initialize the output to the multiplicative identity (1)
  unsigned char constant_term = 1;
  unsigned current_degree, term;
  for (current_degree = 0; current_degree < degree; current_degree ++) {
    // output *= (x - constant_term); addition and subtraction are XOR
    output[current_degree + 1] = output[current_degree];
    for (term = current_degree; term; term --)
      output[term] = qrgen_ECC_multiply(output[term], constant_term) ^ output[term - 1];
    *output = qrgen_ECC_multiply(*output, constant_term);
    constant_term = qrgen_ECC_multiply(constant_term, 2);
  }
}

static unsigned char qrgen_ECC_multiply (unsigned char first, unsigned char second) {
  // traditional bit-shifting-based algorithm; addition is XOR since polynomial coefficients are restricted to {0, 1}
  unsigned char result = 0;
  while (first) {
    if (first & 1) result ^= second;
    first >>= 1;
    second = (second << 1) ^ ((second & 0x80) ? 0x1D : 0);
  }
  return result;
}

static void qrgen_interleave (const unsigned char * data, const unsigned char * ECC, struct qrgen_ECC_parameters parameters, unsigned char * result) {
  const unsigned char * blocks[84]; // enough for the largest case
  unsigned block, pos;
  *blocks = data;
  for (block = 0; block < parameters.blocks; block ++) blocks[block + 1] = blocks[block] + parameters.data_bytes - (block < parameters.short_blocks);
  for (pos = 0; pos < parameters.data_bytes; pos ++) for (block = 0; block < parameters.blocks; block ++) {
    if ((blocks[block] + pos) >= blocks[block + 1]) continue;
    *(result ++) = blocks[block][pos];
  }
  for (pos = 0; pos < parameters.ECC_bytes; pos ++) for (block = 0; block < parameters.blocks; block ++)
    *(result ++) = ECC[block * parameters.ECC_bytes + pos];
}

static int qrgen_build_QR (const unsigned char * data, unsigned char version, unsigned char ECC, unsigned char * result) {
  unsigned char modules[QRGEN_ENCODING_BUFFER_SIZE * 8L]; // index = col * side + row
  unsigned char side = version * 4 + 17;
  memset(modules, QRGEN_EMPTY, side * side);
  qrgen_place_function_patterns(modules, side, version);
  qrgen_place_version_information(modules, side, version);
  qrgen_place_format_information(modules, side, -1);
  modules[9 * side - 8] = QRGEN_BLACK_NONMASKED;
  qrgen_place_data_modules(modules, side, version, data);
  unsigned pos;
  for (pos = 0; pos < (side * side); pos ++) if (modules[pos] == QRGEN_EMPTY) return 3;
  unsigned char masking = qrgen_select_masking(modules, side, ECC);
  qrgen_apply_masking(modules, side, masking, ECC);
  qrgen_export_QR_data(modules, side, result);
  return 0;
}

static void qrgen_place_function_patterns (unsigned char * modules, unsigned char side, unsigned char version) {
  unsigned pos;
  qrgen_place_position_identification_pattern(modules, 0, 0, side);
  qrgen_place_position_identification_pattern(modules, 0, side - 7, side);
  qrgen_place_position_identification_pattern(modules, side - 7, 0, side);
  memset(modules + 7 * side, QRGEN_WHITE_NONMASKED, 8);
  memset(modules + (side - 8) * side, QRGEN_WHITE_NONMASKED, 8);
  memset(modules + 8 * side - 8, QRGEN_WHITE_NONMASKED, 8);
  for (pos = 0; pos < 7; pos ++) {
    modules[pos * side + 7] = QRGEN_WHITE_NONMASKED;
    modules[(pos + 1) * side - 8] = QRGEN_WHITE_NONMASKED;
    modules[(side - 1 - pos) * side + 7] = QRGEN_WHITE_NONMASKED;
  }
  for (pos = 8; pos < (side - 8); pos ++)
    modules[pos * side + 6] = modules[6 * side + pos] = (pos & 1) ? QRGEN_WHITE_NONMASKED : QRGEN_BLACK_NONMASKED;
  qrgen_place_alignment_patterns(modules, side, version);
}

static void qrgen_place_position_identification_pattern (unsigned char * modules, unsigned char row, unsigned char col, unsigned char side) {
  unsigned pos;
  memset(modules + col * side + row, QRGEN_BLACK_NONMASKED, 7);
  memset(modules + (col + 6) * side + row, QRGEN_BLACK_NONMASKED, 7);
  for (pos = 1; pos <= 5; pos ++)
    modules[(col + pos) * side + row] = modules[(col + pos) * side + row + 6] = QRGEN_BLACK_NONMASKED;
  memset(modules + (col + 1) * side + row + 1, QRGEN_WHITE_NONMASKED, 5);
  memset(modules + (col + 5) * side + row + 1, QRGEN_WHITE_NONMASKED, 5);
  for (pos = 2; pos <= 4; pos ++) {
    modules[(col + pos) * side + row + 1] = modules[(col + pos) * side + row + 5] = QRGEN_WHITE_NONMASKED;
    memset(modules + (col + pos) * side + row + 2, QRGEN_BLACK_NONMASKED, 3);
  }
}

static void qrgen_place_alignment_patterns (unsigned char * modules, unsigned char side, unsigned char version) {
  if (version < 2) return;
  unsigned vindex, hindex, row, col, pos, limit = version / 7 + 1;
  for (vindex = 0; vindex <= limit; vindex ++) for (hindex = !vindex; hindex <= limit; hindex ++) {
    if ((vindex == limit) && !hindex) continue;
    if ((hindex == limit) && !vindex) continue;
    row = qrgen_alignment_pattern_position(version, hindex);
    col = qrgen_alignment_pattern_position(version, vindex);
    modules[col * side + row] = QRGEN_BLACK_NONMASKED;
    memset(modules + (col - 1) * side + row - 1, QRGEN_WHITE_NONMASKED, 3);
    memset(modules + (col + 1) * side + row - 1, QRGEN_WHITE_NONMASKED, 3);
    modules[col * side + row - 1] = modules[col * side + row + 1] = QRGEN_WHITE_NONMASKED;
    memset(modules + (col - 2) * side + row - 2, QRGEN_BLACK_NONMASKED, 5);
    memset(modules + (col + 2) * side + row - 2, QRGEN_BLACK_NONMASKED, 5);
    for (pos = col - 1; pos <= (col + 1); pos ++)
      modules[pos * side + row - 2] = modules[pos * side + row + 2] = QRGEN_BLACK_NONMASKED;
  }
}

static unsigned qrgen_compute_polynomial_error_correction (unsigned data, unsigned polynomial, unsigned char length) {
  unsigned result = 0;
  unsigned current = polynomial & ((1 << length) - 1);
  polynomial = current | (1 << length);
  while (data) {
    if (data & 1) result ^= current;
    data >>= 1;
    current <<= 1;
    if (current & (1 << length)) current ^= polynomial;
  }
  return result;
}

static void qrgen_place_version_information (unsigned char * modules, unsigned char side, unsigned char version) {
  if (version < 7) return;
  unsigned data = qrgen_compute_polynomial_error_correction(version, 0xF25, 12);
  data |= (unsigned) version << 12;
  unsigned minor, major, position = side - 11;
  for (major = 0; major < 6; major ++) for (minor = 0; minor < 3; minor ++) {
    modules[major * side + position + minor] = modules[(position + minor) * side + major] = (data & 1) ? QRGEN_BLACK_NONMASKED : QRGEN_WHITE_NONMASKED;
    data >>= 1;
  }
}

static void qrgen_place_format_information (unsigned char * modules, unsigned char side, short data) {
  unsigned char module_value = QRGEN_RESERVED;
  unsigned pos;
  for (pos = 0; pos <= 14; pos ++) {
    if (data >= 0) {
      module_value = (data & 1) ? QRGEN_BLACK_NONMASKED : QRGEN_WHITE_NONMASKED;
      data >>= 1;
    }
    if (pos <= 7)
      modules[8 * side + pos + (pos >= 6)] = modules[(side - 1 - pos) * side + 8] = module_value;
    else if (pos == 8)
      modules[7 * side + 8] = modules[9 * side - 7] = module_value;
    else
      modules[(14 - pos) * side + 8] = modules[9 * side + pos - 15] = module_value;
  }
}

static unsigned short qrgen_compute_format_information (unsigned char ECC, unsigned char masking) {
  unsigned data = ((ECC ^ 1) << 3) | masking;
  unsigned error_correction = qrgen_compute_polynomial_error_correction(data, 0x137, 10);
  data = (data << 10) | error_correction;
  return data ^ 0x5412;
}

static void qrgen_place_data_modules (unsigned char * modules, unsigned char side, unsigned char version, const unsigned char * data) {
  unsigned short length;
  unsigned short scan, index = 0;
  unsigned char value, bit;
  for (length = qrgen_data_bits_for_version(version); length > 7; length -= 8) {
    value = *(data ++);
    for (bit = 7; bit < 8; bit --) {
      do
        scan = qrgen_scan_index(index ++, side);
      while (modules[scan] != QRGEN_EMPTY);
      modules[scan] = (value & (1 << bit)) ? QRGEN_BLACK : QRGEN_WHITE;
    }
  }
  while (length --) {
    do
      scan = qrgen_scan_index(index ++, side);
    while (modules[scan] != QRGEN_EMPTY);
    modules[scan] = QRGEN_WHITE;
  }
}

static unsigned short qrgen_scan_index (unsigned short index, unsigned char side) {
  // converts a sequential scan index into the zigzagging order required by the standard to place data; 0 = bottom right
  // row and col 6 are problematic (timing patterns), so this computation pretends they don't exist
  unsigned char col = index / (2 * side - 2);
  unsigned short row = index % (2 * side - 2);
  col = (col << 1) | (row & 1);
  row >>= 1;
  if (!(col & 2)) row = side - 2 - row;
  col = side - 2 - col;
  if (row > 5) row ++;
  if (col > 5) col ++;
  return (unsigned short) col * side + row;
}

static unsigned char qrgen_select_masking (unsigned char * modules, unsigned char side, unsigned char ECC) {
  unsigned char masking, best_masking, score, best_score;
  best_masking = 0;
  qrgen_apply_masking(modules, side, 0, ECC);
  best_score = qrgen_compute_masking_score(modules, side, 0);
  qrgen_unmask(modules, side);
  for (masking = 1; masking < 8; masking ++) {
    qrgen_apply_masking(modules, side, masking, ECC);
    score = qrgen_compute_masking_score(modules, side, masking);
    qrgen_unmask(modules, side);
    if (score < best_score) {
      best_masking = masking;
      best_score = score;
    }
  }
  return best_masking;
}

static void qrgen_apply_masking (unsigned char * modules, unsigned char side, unsigned char masking, unsigned char ECC) {
  // repeating the same body in each loop (to mask cells) isn't pretty, but it's more efficient than any alternative, and it's just one line
  qrgen_place_format_information(modules, side, qrgen_compute_format_information(ECC, masking));
  unsigned row, col;
  switch (masking) {
    case 0:
      for (col = 0; col < side; col ++) for (row = col & 1; row < side; row += 2)
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      break;
    case 1:
      for (col = 0; col < side; col ++) for (row = 0; row < side; row += 2)
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      break;
    case 2:
      for (col = 0; col < side; col += 3) for (row = 0; row < side; row ++)
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      break;
    case 3:
      for (col = 0; col < side; col ++) for (row = (col % 3) ? 3 - (col % 3) : 0; row < side; row += 3)
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      break;
    case 4:
      for (col = 0; col < side; col ++) for (row = 2 * ((col % 6) >= 3); row < side; row += 4) {
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
        if ((row + 1) == side) continue;
        if (modules[col * side + row + 1] < 2) modules[col * side + row + 1] += QRGEN_MASKING_OFFSET;
      }
      break;
    case 5:
      for (col = 0; col < side; col ++) for (row = 0; row < side; row ++) {
        if ((row * col) % 6) continue;
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      }
      break;
    case 6:
      for (col = 0; col < side; col ++) for (row = 0; row < side; row ++) {
        if (((row * col) % 3 + row * col) & 1) continue;
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      }
      break;
    case 7:
      for (col = 0; col < side; col ++) for (row = 0; row < side; row ++) {
        if (((row * col) % 3 + row + col) & 1) continue;
        if (modules[col * side + row] < 2) modules[col * side + row] += QRGEN_MASKING_OFFSET;
      }
  }
}

static unsigned qrgen_compute_masking_score (unsigned char * modules, unsigned char side, unsigned char masking) {
  // this will also pick up some scoring for the function patterns, but that's the same for all maskings, so it doesn't matter
  unsigned score = 0;
  unsigned short black = 0;
  unsigned short index = 0;
  unsigned char adjacent = 0;
  unsigned char row, col, value;
  for (col = 0; col < side; col ++) {
    for (row = 0; row < side; row ++) {
      if (modules[index] & 1) black ++;
      if (row)
        if ((modules[index] & 1) != (modules[index - 1] & 1)) {
          if (adjacent > 5) score += adjacent - 2;
          adjacent = 0;
        } else
          adjacent ++;
      if (row && col) {
        value = (modules[index] ^ modules[index - 1]) | (modules[index] ^ modules[index - side]) | (modules[index] ^ modules[index - side - 1]);
        if (!(value & 1)) score += 3;
      }
      if (row >= 6) {
        value = modules[index - 6] & modules[index - 4] & modules[index - 3] & modules[index - 2] & modules[index];
        value |= ~(modules[index - 5] | modules[index - 1]);
        if (value & 1) score += 40;
      }
      index ++;
    }
    if (adjacent > 5) score += adjacent - 2;
    adjacent = 0;
  }
  black = (400u * black + 200u) / (side * side);
  if (black > 100) score += black - 100;
  for (row = 0; row < side; row ++) {
    index = row + side;
    for (col = 1; col < side; col ++) {
      if ((modules[index] & 1) != (modules[index - side] & 1)) {
        if (adjacent > 5) score += adjacent - 2;
        adjacent = 0;
      } else
        adjacent ++;
      if (col >= 6) {
        value = modules[index - 6 * side] & modules[index - 4 * side] & modules[index - 3 * side] & modules[index - 2 * side] & modules[index];
        value |= ~(modules[index - 5 * side] | modules[index - side]);
        if (value & 1) score += 40;
      }
      index += side;
    }
    if (adjacent > 5) score += adjacent - 2;
    adjacent = 0;
  }
  // add a tie-breaking criterion; prefer masking fewer cells, and if tied, simpler maskings
  value = masking[(unsigned char []) {4, 3, 1, 2, 5, 0, 7, 6}];
  return (score << 3) | value;
}

static void qrgen_unmask (unsigned char * modules, unsigned char side) {
  unsigned short index, limit = (unsigned short) side * side;
  for (index = 0; index < limit; index ++) if (modules[index] >= QRGEN_MASKING_OFFSET) modules[index] -= QRGEN_MASKING_OFFSET;
  qrgen_place_format_information(modules, side, -1);
}

static void qrgen_export_QR_data (const unsigned char * modules, unsigned char side, unsigned char * result) {
  // MSB = leftmost pixel
  unsigned char row, col, value = 0;
  for (row = 0; row < side; row ++) {
    for (col = 0; col < side; col ++) {
      value = (value << 1) | (modules[col * side + row] & 1);
      if ((col & 7) == 7) *(result ++) = value;
    }
    // all valid side lengths are odd, so they can never be a multiple of 8
    value <<= 8 - (side & 7);
    *(result ++) = value;
  }
}
