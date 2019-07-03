## Compiling the library

The library is just a single file, `libqrgen.c`. You can just add it to your project, or compile it as a shared
library, like so:

```
gcc -O3 -shared -fPIC libqrgen.c -o libqrgen.so
```

The library only depends on the C standard library. It also requires 8-bit chars and will error out if you're somehow
using a machine from the 1970s.

## Using the library

The design idea behind this library is to make it simple. Therefore, it defines just one function in `libqrgen.h`:

```c
unsigned char generate_QR_code(const void * data, unsigned short length,
                               unsigned char target_version, unsigned char limit_version, void * buffer);
```

The `data` and `length` arguments specify the data to be encoded in the QR code and its length. Any binary data can be
encoded.

The size of a QR code is defined by a value called the "version", which goes from 1 to 40. The library will choose a
suitable version for the data, within a range determined by the `target_version` and `limit_version` arguments. The
level of error correction is also chosen by the library; the library will maximize error correction for the chosen
version. If the target version is smaller than the limit, the library will choose the smallest suitable version within
the range; if it is greater, it will maximize error correction (which may yield a larger version).

The `buffer` argument is where the function will store the data; this buffer must be large enough for any version in
the specified range.

The function returns the selected version number, since this parameter is necessary to process the data. If the
function fails (for example, because there is no suitable version number that will contain all of the data), it
returns zero.

The QR code's contents are written to the buffer as a single bit per cell ("module" in the standard's terms). The
order is left to right, top to bottom — that is, the first byte contains the leftmost 8 cells of the top row, the
second byte contains the following 8 cells of that row, and so on. Each row is padded to a whole number of bytes in
order to make vertical scanning easier; the padding bits don't contain any useful information. (Note that QR codes
are always square and always have an odd number of cells per side, so there will always be some padding bits.)  
Within each byte, the most significant bit represents the leftmost cell, and the least significant bit the rightmost.
Bits are set for dark (black) cells and clear for light (white) cells.

The `libqrgen.h` header file defines the following macros to make this buffer easier to handle, all of which take the
version number as argument:

* `QR_PIXELS_PER_SIDE(version)`: number of cells per side. The standard defines this as `4 * version + 17`.
* `QR_BYTES_PER_ROW(version)`: number of bytes for each row in the buffer; this is determined by the number of cells
  per row, rounded up to the next multiple of 8 (since rows are always padded to a whole number of bytes).
* `QR_BUFFER_SIZE(version)`: number of bytes required to store the whole QR code; this is the product of the previous
  two values (i.e., number of rows times bytes per row). This macro will evaluate its argument twice.
