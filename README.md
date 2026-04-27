# eeprom_sign - RSA-PSS sign/verify/flash tool for HAT+ EEPROMs

Sign, verify, and batch-flash Raspberry Pi HAT+ EEPROM binaries.  
Supports single-device and production batch workflows via an
[I2CDriver](https://i2cdriver.com) USB-to-I²C bridge.

## Summary

- [Requirements](#requirements)
- [Subcommands](#subcommands)
  - [keygen](#keygen---generate-an-rsa-key-pair)
  - [sign](#sign---sign-a-single-eeprom-binary)
  - [verify](#verify---verify-a-signed-eeprom-binary-file)
  - [strip](#strip---remove-the-signature-atom)
  - [batch](#batch---batch-sign--flash-loop)
  - [readback](#readback---read-one-eeprom-and-verify-its-signature)
  - [batch-readback](#batch-readback---batch-read--verify-loop)
- [Supported EEPROM models](#supported-eeprom-models)
- [EEPROM image format](#eeprom-image-format)
- [Signature scheme](#signature-scheme)
- [Typical production workflow](#typical-production-workflow)

---

## Installation

### Via homebrew (macOS ARM/Linux)

```zsh
brew tap fred-corp/tap
brew install eeprom-sign
```

or

```zsh
brew install fred-corp/tap/eeprom-sign
```

### Via `pip`

```zsh
pip install eeprom-sign
```

## Requirements

```zsh
pip install cryptography i2cdriver
```

Python 3.10 or later (uses `X | Y` union type hints).

---

## Subcommands

| Subcommand       | What it does                                      |
|------------------|---------------------------------------------------|
| `keygen`         | Generate an RSA key pair                          |
| `sign`           | Sign a single EEPROM binary file                  |
| `verify`         | Verify the signature in a binary file             |
| `strip`          | Remove the signature atom from a binary file      |
| `batch`          | Batch sign + flash loop via I2CDriver             |
| `readback`       | Read one EEPROM over I²C and verify its signature |
| `batch-readback` | Batch read + verify loop via I2CDriver            |

---

### keygen - Generate an RSA key pair

```zsh
eeprom-sign keygen --private FILE --public FILE [--bits BITS]
```

Generates a new RSA private/public key pair and writes both as PEM files.
Keep the private key secret; distribute the public key to anyone who needs
to verify signatures.

#### Arguments

| Argument         | Required | Default | Description                         |
|------------------|----------|---------|-------------------------------------|
| `--private FILE` | yes      | -       | Output path for the private key PEM |
| `--public FILE`  | yes      | -       | Output path for the public key PEM  |
| `--bits BITS`    | no       | `2048`  | Key size: `2048`, `3072`, or `4096` |

#### Example

```zsh
eeprom-sign keygen \
    --private hat_private.pem \
    --public  hat_public.pem
```

---

### sign - Sign a single EEPROM binary

```zsh
eeprom-sign sign INPUT --serial STRING --private FILE --output FILE
```

Takes an existing HAT+ EEPROM binary, embeds a serial number atom (SNUM),
patches the vendor info atom with a fresh UUID, signs the result with
RSA-PSS / SHA-256, and writes the signed image to a new file.

If the input already contains a RSIG or SNUM atom, both are stripped first
so the operation is always idempotent.

#### Arguments

| Argument          | Required | Description                                |
|-------------------|----------|--------------------------------------------|
| `INPUT`           | yes      | Base (unsigned) EEPROM `.bin` file         |
| `--serial STRING` | yes      | Serial number to embed, e.g. `YOTA0001`    |
| `--private FILE`  | yes      | RSA private key PEM file                   |
| `--output FILE`   | yes      | Output path for the signed binary          |

#### Example

```zsh
eeprom-sign sign eeprom_base.bin \
    --serial  YOTA0001 \
    --private hat_private.pem \
    --output  eeprom_signed.bin
```

---

### verify - Verify a signed EEPROM binary file

```zsh
eeprom-sign verify INPUT --public FILE
```

Locates the RSIG atom in the binary, reconstructs the exact byte sequence
that was signed, and verifies the RSA-PSS signature. Exits with a non-zero
status and an error message if verification fails.

#### Arguments

| Argument          | Required | Description                |
|-------------------|----------|----------------------------|
| `INPUT`           | yes      | Signed EEPROM `.bin` file  |
| `--public FILE`   | yes      | RSA public key PEM file    |

#### Example

```zsh
eeprom-sign verify eeprom_signed.bin \
    --public hat_public.pem
```

---

### strip - Remove the signature atom

```zsh
eeprom-sign strip INPUT --output FILE
```

Removes the RSIG atom and updates the EEPROM header (`numatoms`, `eeplen`)
so the result is a valid unsigned image ready for re-signing.

#### Arguments

| Argument          | Required | Description                            |
|-------------------|----------|----------------------------------------|
| `INPUT`           | yes      | Signed EEPROM `.bin` file              |
| `--output FILE`   | yes      | Output path for the stripped binary    |

#### Example

```zsh
eeprom-sign strip eeprom_signed.bin \
    --output eeprom_base.bin
```

---

### batch - Batch sign + flash loop

```zsh
eeprom-sign batch INPUT \
    --serial STRING --private FILE \
    [--public FILE] [--eeprom MODEL] [--port PORT] \
    [--output-dir DIR] [--no-verify] [--auto-detect]
```

Interactive production loop. For each board it:

1. Waits for the operator (Enter key) or for the EEPROM to appear on the
   bus (`--auto-detect`).
2. Detects the EEPROM at I²C address `0x50` (falls back to a full scan of
   `0x50`–`0x57` if nothing responds there).
3. Generates a **fresh UUID** (patched into the vendor info atom) and an
   **incremented serial number**.
4. Signs the image with RSA-PSS / SHA-256.
5. Flashes the EEPROM using page-aligned writes with ACK-poll completion.
6. Verifies the readback byte-for-byte. Optionally also verifies the RSA
   signature in memory if `--public` is supplied.
7. Optionally saves the signed binary to `--output-dir`.
8. Advances the serial counter and loops.

Press **Ctrl+C** to stop. The last flashed serial and the next one to use
are printed on exit.

#### Arguments

| Argument              | Required  | Default           | Description                                                                                                                           |
|-----------------------|-----------|-------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `INPUT`               | yes       | -                 | Base (unsigned) EEPROM `.bin` image                                                                                                   |
| `--serial STRING`     | yes       | -                 | Starting serial, e.g. `YOTA0001`. The trailing digits are incremented for each board; the width and prefix are preserved.             |
| `--private FILE`      | yes       | -                 | RSA private key PEM file                                                                                                              |
| `--public FILE`       | no        | -                 | RSA public key PEM file. If supplied, a full crypto verify is run after each flash in addition to the byte-for-byte readback check.   |
| `--eeprom MODEL`      | no        | `24c256`          | EEPROM model. See [Supported EEPROM models](#supported-eeprom-models).                                                                |
| `--port PORT`         | no        | `/dev/ttyUSB0`    | Serial port of the I2CDriver. macOS example: `/dev/tty.usbserial-DM02V7KY`. Windows example: `COM3`.                                  |
| `--output-dir DIR`    | no        | -                 | Save each signed `.bin` as `<serial>.bin` in this directory.                                                                          |
| `--no-verify`         | no        | off               | Skip the post-flash crypto signature verification (byte-for-byte readback is always performed).                                       |
| `--auto-detect`       | no        | off               | Flash automatically when a board is inserted - no Enter needed. Useful on pogo-pin fixtures.                                          |

#### Examples

```zsh
# Manual mode (press Enter per board), save signed binaries
eeprom-sign batch eeprom_base.bin \
    --serial     YOTA0001 \
    --private    hat_private.pem \
    --public     hat_public.pem \
    --eeprom     24c256 \
    --port       /dev/tty.usbserial-DM02V7KY \
    --output-dir ./signed_images

# Auto-detect mode, no file saving, no crypto re-verify
eeprom-sign batch eeprom_base.bin \
    --serial    YOTA0001 \
    --private   hat_private.pem \
    --eeprom    24c256 \
    --port      /dev/tty.usbserial-DM02V7KY \
    --auto-detect \
    --no-verify
```

---

### readback - Read one EEPROM and verify its signature

```zsh
eeprom-sign readback \
    --public FILE [--eeprom MODEL] [--port PORT] [--output FILE]
```

Reads the EEPROM contents over I²C, prints the vendor/product strings,
UUID, and serial number found in the atoms, then verifies the RSA-PSS
signature. Optionally saves the raw binary.

The tool reads only as many bytes as `eeplen` in the HAT+ header specifies,
so it is fast regardless of chip capacity.

#### Arguments

| Argument          | Required  | Default           | Description                               |
|-------------------|-----------|-------------------|-------------------------------------------|
| `--public FILE`   | yes       | -                 | RSA public key PEM file                   |
| `--eeprom MODEL`  | no        | `24c256`          | EEPROM model                              |
| `--port PORT`     | no        | `/dev/ttyUSB0`    | I2CDriver serial port                     |
| `--output FILE`   | no        | -                 | Save the raw binary read from the chip    |

#### Examples

```zsh
eeprom-sign readback \
    --public hat_public.pem \
    --eeprom 24c256 \
    --port   /dev/tty.usbserial-DM02V7KY \
    --output readback.bin
```

#### Sample output

```txt
[i2c] Connected to I2CDriver on /dev/tty.usbserial-DM02V7KY
[readback] Detecting EEPROM…
[readback] Found EEPROM at 0x50
[readback] Reading 412 bytes…
[readback] 4 atom(s) found
         Vendor  : ACME Ltd
         Product : Sensor HAT
         UUID    : 3f2a1b4c-…
         Serial  : BATCH0003
[verify] ✓  Signature VALID - tmp_xxxx.bin
         RSA-2048 / SHA-256 / PSS
```

---

### batch-readback - Batch read + verify loop

```zsh
eeprom-sign batch-readback \
    --public FILE [--eeprom MODEL] [--port PORT] \
    [--output-dir DIR] [--auto-detect]
```

Read and verify multiple boards in sequence. Mirrors the `batch` workflow
but is read-only - useful for post-flash QC or incoming inspection.

#### Arguments

| Argument              | Required  | Default           | Description                                       |
|-----------------------|-----------|-------------------|---------------------------------------------------|
| `--public FILE`       | yes       | -                 | RSA public key PEM file                           |
| `--eeprom MODEL`      | no        | `24c256`          | EEPROM model                                      |
| `--port PORT`         | no        | `/dev/ttyUSB0`    | I2CDriver serial port                             |
| `--output-dir DIR`    | no        | -                 | Save each readback as `readback_NNNN.bin`         |
| `--auto-detect`       | no        | off               | Trigger read on board insertion (no Enter needed) |

#### Examples

```zsh
# Manual mode
eeprom-sign batch-readback \
    --public hat_public.pem \
    --eeprom 24c256 \
    --port   /dev/tty.usbserial-DM02V7KY

# Auto-detect, save all readbacks
eeprom-sign batch-readback \
    --public     hat_public.pem \
    --eeprom     24c256 \
    --port       /dev/tty.usbserial-DM02V7KY \
    --auto-detect \
    --output-dir ./qc_readbacks
```

---

## Supported EEPROM models

| `--eeprom` value  | Capacity  | Page size | Notes         |
|-------------------|-----------|-----------|---------------|
| `24c32`           | 4 KiB     | 32 B      |               |
| `24c64`           | 8 KiB     | 32 B      |               |
| `24c128`          | 16 KiB    | 64 B      |               |
| `24c256`          | 32 KiB    | 64 B      | **Default**   |
| `24c512`          | 64 KiB    | 128 B     |               |
| `24c1024`         | 128 KiB   | 128 B     |               |

All models use I²C address `0x50` when address pins `A2`/`A1`/`A0` are
tied to GND, which is standard on HAT+ boards. The tool probes `0x50`
first and falls back to a full scan of `0x50`–`0x57` if needed.

---

## EEPROM image format

The tool follows the [HAT+ EEPROM specification](https://datasheets.raspberrypi.com/hat/hat-plus-specification.pdf).

### File header (12 bytes)

| Offset | Size | Field.     | Value                                    |
|--------|------|------------|------------------------------------------|
| 0      | 4    | Magic      | `0x69502d52` ("R-Pi")                    |
| 4      | 1    | Version    |                                          |
| 5      | 1    | Reserved   |                                          |
| 6      | 2    | `numatoms` | atom count (LE uint16)                   |
| 8      | 4    | `eeplen`   | total image size in bytes (LE uint32)    |

### Atom layout

| Offset   | Size   | Field                                 |
|----------|--------|---------------------------------------|
| 0        | 2      | `type` (LE uint16)                    |
| 2        | 2      | `count` (atom index, LE uint16)       |
| 4        | 4      | `dlen` (data + CRC length, LE uint32) |
| 8        | dlen−2 | data                                  |
| 8+dlen−2 | 2      | CRC-16/ARC over header+data           |

### Atom types used by this tool

| Type                    | Name          | Description                                                                                                                       |
|-------------------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `0x0001`                | Vendor info   | UUID, PID, version, vendor/product strings. The 16-byte UUID field is overwritten with a fresh `uuid4()` on every sign operation. |
| `0x0004` + magic `RSIG` | Signature     | RSA-PSS / SHA-256 signature (256 bytes for RSA-2048).                                                                             |
| `0x0004` + magic `SNUM` | Serial number | ASCII serial string embedded by `sign` and `batch`.                                                                               |

---

## Signature scheme

- **Algorithm:** RSA-PSS with MGF1-SHA-256 and maximum salt length.
- **Signed payload:** every byte of the image from offset 0 up to (but not
  including) the RSIG atom header, with `numatoms` and `eeplen` in the
  file header already reflecting the final atom count and total size.  This
  means the UUID, serial number, and all standard HAT+ atoms are all
  covered by the signature.
- **Verification:** the verifier reconstructs the same byte range from the
  image on disk (or read from the chip) and calls
  `public_key.verify(…, PSS(…), SHA256())`.

---

## Typical production workflow

```txt
                ┌─────────────────────────────────┐
                │  1. keygen (once, off-line)      │
                │     hat_private.pem              │
                │     hat_public.pem               │
                └──────────────┬──────────────────┘
                               │
                ┌──────────────▼──────────────────┐
                │  2. batch                        │
                │     Base image + private key     │
                │     → unique UUID + serial       │
                │     → sign → flash → verify      │
                └──────────────┬──────────────────┘
                               │
                ┌──────────────▼──────────────────┐
                │  3. batch-readback  (QC)         │
                │     Public key only              │
                │     → read → verify signature    │
                └─────────────────────────────────┘
```

## License & Acknowledgements

Made with ❤️, lots of ☕️, and lack of 🛌  
Published under CreativeCommons BY-SA 4.0

[![Creative Commons License](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)](http://creativecommons.org/licenses/by-sa/4.0/)  
This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).
