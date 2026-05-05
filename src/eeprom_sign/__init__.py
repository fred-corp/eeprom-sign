#!/usr/bin/env python3
"""
eeprom_sign.py — RSA-PSS sign/verify tool for HAT+ EEPROM binaries.

EEPROM atom layout (HAT+ spec):
  Offset  Size  Field
  0       2     type     (little-endian uint16)
  2       2     count    (atom index, little-endian uint16)
  4       4     dlen     (data length in bytes, little-endian uint32)
  8       dlen  data
  8+dlen  2     CRC16    (covers type+count+dlen+data)

Signature atom (type 0x0004, custom data):
  data[0:4]  = magic b'RSIG'  — identifies this as an RSA signature atom
  data[4:8]  = flags uint32 LE  — bit 0: PSS padding; bits 1-7: hash id (0=SHA-256)
  data[8:]   = raw RSA signature bytes (256 bytes for RSA-2048)

The signed payload is every byte of the EEPROM image up to (but NOT including)
the signature atom header, i.e. the original image with its header updated to
reflect the new numatoms count and eeplen.

EEPROM header layout (first 12 bytes):
  0   4   signature  0x69502d52 ("R-Pi")
  4   1   version
  5   1   reserved
  6   2   numatoms   (little-endian uint16)
  8   4   eeplen     (little-endian uint32)

Vendor Info atom (type 0x0001) data layout (HAT+ spec):
  0    16   uuid        (UUID as 16 raw bytes, RFC 4122)
  16    2   pid         (product ID, little-endian uint16)
  18    2   pver        (product version, little-endian uint16)
  20    1   vslen       (vendor string length including NUL)
  21    1   pslen       (product string length including NUL)
  22+       vendor string (NUL-terminated)
  22+vslen  product string (NUL-terminated)

Supported EEPROM models (--eeprom):
  24c32   —   4 KiB,  32 pages of 32 B,  I²C 7-bit addr 0x50-0x57
  24c64   —   8 KiB,  64 pages of 32 B
  24c128  —  16 KiB,  64 pages of 64 B
  24c256  —  32 KiB, 128 pages of 64 B   ← default
  24c512  —  64 KiB, 128 pages of 128 B
  24c1024 — 128 KiB, 256 pages of 128 B
"""

import argparse
import re
import struct
import sys
import time
import uuid as uuid_mod
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ── CRC-16/ARC (used by the HAT+ spec) ─────────────────────────────────────

def crc16(data: bytes) -> int:
    crc = 0x0000
    poly = 0xA001  # reflected 0x8005
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc & 0xFFFF


# ── Atom helpers ──────────────────────────────────────────────────────────────

ATOM_HEADER_SIZE = 8   # type(2) + count(2) + dlen(4)
ATOM_CRC_SIZE    = 2

MAGIC      = b'RSIG'
FLAGS      = 0x00000001    # bit-0 = PSS, bits 1-7 hash id = 0 (SHA-256)

SNUM_MAGIC = b'SNUM'
SNUM_TYPE  = 0x0004

VENDOR_ATOM_TYPE = 0x0001  # HAT+ vendor info atom


def build_atom(atom_type: int, atom_index: int, payload: bytes) -> bytes:
    """Pack a complete atom including CRC."""
    dlen   = len(payload) + ATOM_CRC_SIZE
    header = struct.pack('<HHI', atom_type, atom_index, dlen)
    body   = header + payload
    crc    = crc16(body)
    return body + struct.pack('<H', crc)


def iter_atoms(data: bytes):
    """Yield (offset, type, count, payload_bytes) for each atom."""
    off = 12   # skip the 12-byte EEPROM header
    while off < len(data):
        if off + ATOM_HEADER_SIZE > len(data):
            break
        atype, acount, dlen = struct.unpack_from('<HHI', data, off)
        payload_end = off + ATOM_HEADER_SIZE + dlen - ATOM_CRC_SIZE
        payload     = data[off + ATOM_HEADER_SIZE : payload_end]
        yield off, atype, acount, payload
        off = off + ATOM_HEADER_SIZE + dlen


def count_atoms(data: bytes) -> int:
    return struct.unpack_from('<H', data, 6)[0]


def has_sig_atom(data: bytes) -> bool:
    for _, atype, _, payload in iter_atoms(data):
        if atype == 0x0004 and payload[:4] == MAGIC:
            return True
    return False


def find_atom(data: bytes, atom_type: int, magic: bytes = None):
    """Return (offset, payload) of first matching atom, or (None, None)."""
    for off, atype, _, payload in iter_atoms(data):
        if atype == atom_type:
            if magic is None or payload.startswith(magic):
                return off, payload
    return None, None


def strip_atom(data: bytes, atom_type: int, magic: bytes = None) -> bytearray:
    """Remove a specific atom and fix header (numatoms, eeplen)."""
    off, payload = find_atom(data, atom_type, magic)
    if off is None:
        return bytearray(data)

    atype, acount, dlen = struct.unpack_from('<HHI', data, off)
    atom_len = ATOM_HEADER_SIZE + dlen

    new_data = bytearray(data[:off] + data[off + atom_len:])
    numatoms = count_atoms(new_data) - 1
    struct.pack_into('<H', new_data, 6, numatoms)
    struct.pack_into('<I', new_data, 8, len(new_data))
    return new_data


def strip_snum_atom(data: bytes) -> bytearray:
    return strip_atom(data, SNUM_TYPE, SNUM_MAGIC)


def build_serial_atom(atom_index: int, serial: bytes) -> bytes:
    payload = SNUM_MAGIC + serial
    return build_atom(SNUM_TYPE, atom_index, payload)


# ── Vendor Info atom UUID patching ────────────────────────────────────────────

def patch_vendor_uuid(data: bytearray, new_uuid: uuid_mod.UUID) -> None:
    """
    Overwrite the 16-byte UUID field inside the vendor info atom (type 0x0001)
    in-place.  Also recomputes the atom CRC.

    The UUID is stored as 16 raw bytes in RFC 4122 big-endian wire format
    (same as uuid.UUID.bytes).
    """
    for off, atype, acount, payload in iter_atoms(data):
        if atype != VENDOR_ATOM_TYPE:
            continue
        if len(payload) < 16:
            raise ValueError("Vendor info atom payload too short to contain a UUID")

        # Patch UUID bytes at payload offset 0
        uuid_bytes = new_uuid.bytes
        payload_start = off + ATOM_HEADER_SIZE

        # Write new UUID
        data[payload_start : payload_start + 16] = uuid_bytes

        # Recompute CRC over header + full payload
        atype_c, acount_c, dlen_c = struct.unpack_from('<HHI', data, off)
        header_bytes  = struct.pack('<HHI', atype_c, acount_c, dlen_c)
        full_payload  = bytes(data[payload_start : payload_start + dlen_c - ATOM_CRC_SIZE])
        new_crc       = crc16(header_bytes + full_payload)
        crc_off       = payload_start + dlen_c - ATOM_CRC_SIZE
        struct.pack_into('<H', data, crc_off, new_crc)
        return

    raise ValueError("No vendor info atom (type 0x0001) found in image")


# ── Serial number helpers ─────────────────────────────────────────────────────

_SERIAL_RE = re.compile(r'^(.*?)(\d+)$')

def parse_serial(serial_str: str) -> tuple[str, str, int]:
    """
    Split a serial like 'BATCH0001' into (prefix='BATCH', digits='0001', value=1).
    Raises ValueError if no trailing digits found.
    """
    m = _SERIAL_RE.match(serial_str)
    if not m:
        raise ValueError(
            f"Serial '{serial_str}' must end with digits, e.g. 'BATCH0001'"
        )
    prefix  = m.group(1)
    digits  = m.group(2)
    return prefix, digits, int(digits)


def format_serial(prefix: str, width: int, value: int) -> str:
    return f"{prefix}{value:0{width}d}"


# ── EEPROM model table ────────────────────────────────────────────────────────

EEPROM_MODELS = {
    # name       : (capacity_bytes, page_size_bytes)
    '24c32'  : (4   * 1024,  32),
    '24c64'  : (8   * 1024,  32),
    '24c128' : (16  * 1024,  64),
    '24c256' : (32  * 1024,  64),
    '24c512' : (64  * 1024, 128),
    '24c1024': (128 * 1024, 128),
}

# All 24Cxxx chips respond on 0x50 (A2=A1=A0=0)
I2C_BASE_ADDR = 0x50

# ── I²C / I2CDriver helpers ───────────────────────────────────────────────────

def _require_i2cdriver():
    try:
        from i2cdriver import I2CDriver  # type: ignore
        return I2CDriver
    except ImportError:
        sys.exit(
            "[batch] ERROR: 'i2cdriver' Python package not found.\n"
            "  Install with:  pip install i2cdriver\n"
            "  (or:  pip install i2cdriver --break-system-packages)"
        )


def open_i2cdriver(port: str):
    """Open an I2CDriver connection and return the object."""
    I2CDriver = _require_i2cdriver()
    try:
        drv = I2CDriver(port)
        print(f"[i2c] Connected to I2CDriver on {port}")
        return drv
    except Exception as exc:
        sys.exit(f"[i2c] ERROR: Could not open I2CDriver on {port}: {exc}")


def detect_eeprom(drv) -> int | None:
    """
    Try 0x50 first (the default when A2=A1=A0=GND).
    If nothing answers, fall back to drv.scan() and return the first
    address in 0x50-0x57, or None.
    """
    present = drv.scan(silent=True)
    for addr in present:
        if I2C_BASE_ADDR <= addr <= I2C_BASE_ADDR + 7:
            return addr
    return None


def _eeprom_wait_ready(drv, addr: int, timeout: float = 0.5) -> None:
    """
    Poll-for-ACK after a page write.

    The 24Cxxx holds NACK during its internal write cycle (≤5 ms typ,
    ≤10 ms max).  drv.start(addr, 0) returns True on ACK, False on NACK,
    so we poll that directly — much faster than a full bus scan.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        acked = drv.start(addr, 0)
        drv.stop()
        if acked:
            return
        time.sleep(0.001)
    raise TimeoutError(
        f"EEPROM at 0x{addr:02X} did not become ready within {timeout:.1f}s"
    )


def eeprom_write(drv, addr: int, offset: int, data: bytes, page_size: int) -> None:
    """
    Write *data* to a 24Cxxx EEPROM at I²C address *addr* starting at byte
    offset *offset*, using page-aligned writes of up to *page_size* bytes.

    Each page write is:
        START(addr,W)  [addr_hi] [addr_lo]  [data…]  STOP
    then we poll for ACK before moving to the next page.

    The i2cdriver write() method sends at most 64 bytes per USB frame
    internally, so we don't need to worry about that limit here — we just
    keep our writes ≤ page_size.
    """
    written = 0
    total   = len(data)

    while written < total:
        cur_off = offset + written

        # How many bytes until the next page boundary?
        page_space = page_size - (cur_off % page_size)
        chunk_size = min(page_space, total - written)
        chunk      = data[written : written + chunk_size]

        addr_hi = (cur_off >> 8) & 0xFF
        addr_lo =  cur_off       & 0xFF

        drv.start(addr, 0)                              # START + address byte
        drv.write(bytes([addr_hi, addr_lo]) + chunk)    # mem addr + data
        drv.stop()                                       # STOP — triggers write

        _eeprom_wait_ready(drv, addr)                   # poll until ACK
        written += chunk_size


def eeprom_read(drv, addr: int, offset: int, length: int) -> bytes:
    """
    Sequential read from a 24Cxxx EEPROM.

    Protocol:
        START(addr,W)  [addr_hi] [addr_lo]   ← set address pointer
        START(addr,R)  read(length)  STOP     ← repeated-start then read
    """
    addr_hi = (offset >> 8) & 0xFF
    addr_lo =  offset       & 0xFF

    drv.start(addr, 0)                   # write-mode to set address
    drv.write(bytes([addr_hi, addr_lo]))
    drv.start(addr, 1)                   # repeated-start, switch to read
    result = drv.read(length)
    drv.stop()
    return bytes(result)


def eeprom_verify(drv, addr: int, offset: int, expected: bytes) -> bool:
    """Read back *len(expected)* bytes and compare."""
    actual = eeprom_read(drv, addr, offset, len(expected))
    return actual == expected


# ── Key management ────────────────────────────────────────────────────────────

def generate_keypair(private_key_path: Path, public_key_path: Path, key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"[keygen] Private key → {private_key_path}")
    print(f"[keygen] Public  key → {public_key_path}")


def load_private_key(path: Path):
    return serialization.load_pem_private_key(
        path.read_bytes(), password=None, backend=default_backend()
    )


def load_public_key(path: Path):
    return serialization.load_pem_public_key(
        path.read_bytes(), backend=default_backend()
    )


# ── Sign (core, returns bytes) ────────────────────────────────────────────────

def _sign_image(base_image: bytes, private_key, serial_str: str) -> bytes:
    """
    Given a *base* EEPROM image (no RSIG, no SNUM), embed a fresh UUID,
    append a SNUM atom, sign, and return the final binary.
    """
    data = bytearray(base_image)

    # ── Fresh UUID in vendor info atom ─────────────────────────────────────
    new_uuid = uuid_mod.uuid4()
    try:
        patch_vendor_uuid(data, new_uuid)
        print(f"         UUID    : {new_uuid}")
    except ValueError as e:
        print(f"[sign] WARNING: {e} — UUID not patched")

    private_key_obj = private_key
    sig_size = private_key_obj.key_size // 8

    # ── Serial atom ────────────────────────────────────────────────────────
    serial_bytes   = serial_str.encode('ascii')
    old_numatoms   = count_atoms(data)
    serial_atom    = build_serial_atom(old_numatoms, serial_bytes)
    data_with_serial = data + serial_atom

    # ── Header update (serial atom + sig atom) ─────────────────────────────
    new_numatoms = old_numatoms + 2

    sig_payload  = MAGIC + struct.pack('<I', FLAGS) + bytes(sig_size)
    sig_atom_len = ATOM_HEADER_SIZE + len(sig_payload) + ATOM_CRC_SIZE
    new_eeplen   = len(data_with_serial) + sig_atom_len

    signed_image = bytearray(data_with_serial)
    struct.pack_into('<H', signed_image, 6, new_numatoms)
    struct.pack_into('<I', signed_image, 8, new_eeplen)

    # ── Sign ───────────────────────────────────────────────────────────────
    signature = private_key_obj.sign(
        bytes(signed_image),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # ── Signature atom ─────────────────────────────────────────────────────
    real_payload = MAGIC + struct.pack('<I', FLAGS) + signature
    sig_atom     = build_atom(0x0004, new_numatoms - 1, real_payload)

    return bytes(signed_image) + sig_atom


# ── Sign subcommand ───────────────────────────────────────────────────────────

def sign_eeprom(input_path: Path, output_path: Path, private_key_path: Path, serial: str):
    data = bytearray(input_path.read_bytes())

    if has_sig_atom(data):
        data = strip_atom(data, 0x0004, MAGIC)
    data = strip_snum_atom(data)

    print(f"[sign] Normalized image: {count_atoms(data)} atoms")
    print(f"       Serial  : {serial}")

    private_key = load_private_key(private_key_path)
    final_image = _sign_image(bytes(data), private_key, serial)

    output_path.write_bytes(final_image)
    print(f"[sign] Signed image ({len(final_image)} bytes) → {output_path}")




# ── Verify ────────────────────────────────────────────────────────────────────

def verify_eeprom(input_path: Path, public_key_path: Path):
    data       = input_path.read_bytes()
    public_key = load_public_key(public_key_path)

    sig_atom_offset = None
    sig_payload     = None
    for off, atype, _, payload in iter_atoms(data):
        if atype == 0x0004 and payload[:4] == MAGIC:
            sig_atom_offset = off
            sig_payload     = payload
            break

    if sig_atom_offset is None:
        sys.exit("[verify] ERROR: No RSIG atom found in this EEPROM image.")

    flags     = struct.unpack_from('<I', sig_payload, 4)[0]
    signature = sig_payload[8:]

    if not (flags & 0x1):
        sys.exit("[verify] ERROR: flags indicate non-PSS padding — unsupported.")

    original_part = bytearray(data[:sig_atom_offset])
    total_len     = len(data)
    numatoms      = count_atoms(data)
    struct.pack_into('<H', original_part, 6, numatoms)
    struct.pack_into('<I', original_part, 8, total_len)

    try:
        public_key.verify(
            signature,
            bytes(original_part),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print(f"[verify] ✓  Signature VALID — {input_path.name}")
        print(f"         RSA-{public_key.key_size} / SHA-256 / PSS")
    except Exception as exc:
        sys.exit(f"[verify] ✗  Signature INVALID: {exc}")


# ── Strip ─────────────────────────────────────────────────────────────────────

def strip_eeprom(input_path: Path, output_path: Path):
    data = bytearray(input_path.read_bytes())

    sig_atom_offset = None
    for off, atype, _, payload in iter_atoms(data):
        if atype == 0x0004 and payload[:4] == MAGIC:
            sig_atom_offset = off
            break

    if sig_atom_offset is None:
        sys.exit("[strip] No RSIG atom found — nothing to strip.")

    stripped = bytearray(data[:sig_atom_offset])
    numatoms = count_atoms(stripped) - 1
    struct.pack_into('<H', stripped, 6, numatoms)
    struct.pack_into('<I', stripped, 8, len(stripped))

    output_path.write_bytes(bytes(stripped))
    print(f"[strip] Stripped image ({len(stripped)} bytes) → {output_path}")


# ── Batch flashing ────────────────────────────────────────────────────────────

def batch_flash(
    input_path      : Path,
    private_key_path: Path,
    public_key_path : Path | None,
    serial_start    : str,
    eeprom_model    : str,
    port            : str,
    output_dir      : Path | None,
    no_verify       : bool,
    auto_detect     : bool = False,
):
    """
    Batch sign+flash loop.

    auto_detect=False (default): prompt "Press Enter" before each board.
    auto_detect=True:            flash immediately on board insertion,
                                 no keypress needed.
    """

    # ── Validate EEPROM model ──────────────────────────────────────────────
    model_key = eeprom_model.lower().replace('-', '').replace(' ', '')
    if model_key not in EEPROM_MODELS:
        sys.exit(
            f"[batch] ERROR: Unknown EEPROM model '{eeprom_model}'.\n"
            f"  Supported: {', '.join(EEPROM_MODELS)}"
        )
    capacity, page_size = EEPROM_MODELS[model_key]
    print(f"[batch] EEPROM model : {model_key}  "
          f"({capacity//1024} KiB, {page_size}-byte pages)")

    # ── Parse serial ───────────────────────────────────────────────────────
    try:
        prefix, digits_str, serial_value = parse_serial(serial_start)
    except ValueError as e:
        sys.exit(f"[batch] ERROR: {e}")
    digit_width = len(digits_str)
    print(f"[batch] Serial start : {serial_start}  "
          f"(prefix='{prefix}', width={digit_width})")

    # ── Load and normalise base image ──────────────────────────────────────
    base_data = bytearray(input_path.read_bytes())
    if has_sig_atom(base_data):
        base_data = strip_atom(base_data, 0x0004, MAGIC)
    base_data = strip_snum_atom(base_data)
    print(f"[batch] Base image   : {len(base_data)} bytes, "
          f"{count_atoms(base_data)} atoms (normalised)")

    # ── Load private key (once) ────────────────────────────────────────────
    private_key = load_private_key(private_key_path)
    print(f"[batch] Private key  : {private_key_path}")

    public_key = None
    if public_key_path and public_key_path.exists():
        public_key = load_public_key(public_key_path)
        print(f"[batch] Public  key  : {public_key_path}  (verify enabled)")
    elif not no_verify:
        print("[batch] WARNING: No public key supplied; readback verify will "
              "be byte-for-byte only (no crypto check).")

    # ── Output directory ───────────────────────────────────────────────────
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"[batch] Output dir   : {output_dir}")

    # ── Open I2CDriver ─────────────────────────────────────────────────────
    drv = open_i2cdriver(port)

    flashed_count = 0
    board_present = detect_eeprom(drv) is not None

    print()
    print("=" * 60)
    if auto_detect:
        print("  Auto-detect mode — insert board to trigger flash.")
    else:
        print("  Manual mode — press Enter to flash each board.")
    print("  Ctrl+C at any time to stop.")
    print("=" * 60)

    try:
        while True:
            serial_str = format_serial(prefix, digit_width, serial_value)

            if auto_detect:
                # Wait for removal of any board that's already there
                if board_present:
                    print(f"[batch] Waiting for board removal…",
                          end='\r', flush=True)
                    while detect_eeprom(drv) is not None:
                        time.sleep(0.1)
                    board_present = False
                    print(f"[batch] Board removed.  "
                          f"Waiting for next insertion…",
                          end='\r', flush=True)

                # Wait for insertion
                eeprom_addr = None
                while eeprom_addr is None:
                    eeprom_addr = detect_eeprom(drv)
                    if eeprom_addr is None:
                        time.sleep(0.1)
                board_present = True
                print()  # newline after \r
                print(f"[batch] Board detected at 0x{eeprom_addr:02X} — "
                      f"serial {serial_str}")

            else:
                print()
                print(f"  Next serial : {serial_str}")
                print("  Connect board and press [Enter] to flash "
                      "(or Ctrl+C to quit)…", end='', flush=True)
                try:
                    input()
                except EOFError:
                    pass

                # ── Detect EEPROM ──────────────────────────────────────────
                eeprom_addr = detect_eeprom(drv)
                if eeprom_addr is None:
                    print("[batch] ✗  No EEPROM detected on 0x50–0x57.")
                    print("         Check wiring/power, then press [Enter] to retry "
                          "with the same serial, or Ctrl+C to quit…",
                          end='', flush=True)
                    try:
                        input()
                    except EOFError:
                        pass
                    continue

            print(f"[batch]    EEPROM at I²C address 0x{eeprom_addr:02X}")

            # ── Sign image ─────────────────────────────────────────────────
            print(f"[batch] Signing …")
            print(f"         Serial  : {serial_str}")
            final_image = _sign_image(bytes(base_data), private_key, serial_str)

            if len(final_image) > capacity:
                print(f"[batch] ✗  Signed image ({len(final_image)} B) exceeds "
                      f"EEPROM capacity ({capacity} B). Aborting this device.")
                continue

            # ── Flash ──────────────────────────────────────────────────────
            print(f"[batch] Flashing  {len(final_image)} bytes…")
            try:
                eeprom_write(drv, eeprom_addr, 0, final_image, page_size)
            except Exception as exc:
                print(f"[batch] ✗  Flash FAILED: {exc}")
                continue

            # ── Verify readback ────────────────────────────────────────────
            print(f"[batch] Verifying readback…")
            try:
                ok = eeprom_verify(drv, eeprom_addr, 0, final_image)
            except Exception as exc:
                print(f"[batch] ✗  Readback error: {exc}")
                continue

            if not ok:
                print(f"[batch] ✗  Readback MISMATCH — device may be faulty.")
                continue

            print(f"[batch] ✓  Flash+verify OK")

            # ── Optional crypto verify ─────────────────────────────────────
            if public_key and not no_verify:
                sig_atom_offset = None
                sig_payload_v   = None
                for off, atype, _, payload in iter_atoms(final_image):
                    if atype == 0x0004 and payload[:4] == MAGIC:
                        sig_atom_offset = off
                        sig_payload_v   = payload
                        break

                if sig_atom_offset is not None:
                    signature_v = sig_payload_v[8:]
                    original_v  = bytearray(final_image[:sig_atom_offset])
                    struct.pack_into('<H', original_v, 6, count_atoms(final_image))
                    struct.pack_into('<I', original_v, 8, len(final_image))
                    try:
                        public_key.verify(
                            signature_v,
                            bytes(original_v),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )
                        print(f"[batch] ✓  Signature verified")
                    except Exception as exc:
                        print(f"[batch] ✗  Signature INVALID: {exc}")
                        continue

            # ── Save file ──────────────────────────────────────────────────
            if output_dir:
                out_file = output_dir / f"{serial_str}.bin"
                out_file.write_bytes(final_image)
                print(f"[batch]    Saved → {out_file}")

            flashed_count += 1
            serial_value  += 1

            print(f"[batch] ── Device {flashed_count} done ──  "
                  f"(next serial: {format_serial(prefix, digit_width, serial_value)})")

    except KeyboardInterrupt:
        print(f"\n\n[batch] Stopped by user.  "
              f"{flashed_count} device(s) flashed successfully.")
        if flashed_count > 0:
            last_serial = format_serial(prefix, digit_width, serial_value - 1)
            next_serial = format_serial(prefix, digit_width, serial_value)
            print(f"         Last serial flashed : {last_serial}")
            print(f"         Next serial to use  : {next_serial}")



# ── Readback + verify from physical EEPROM ────────────────────────────────────

def _read_and_verify_one(
    drv,
    addr            : int,
    capacity        : int,
    public_key_path : Path,
    output_path     : Path | None,
    tag             : str = "readback",
) -> bool:
    """
    Read one EEPROM, print its atoms, verify signature.
    Returns True on success, False on any error (so batch loops can continue).
    """
    import tempfile, os

    # ── Read header to get eeplen ──────────────────────────────────────────
    try:
        header = eeprom_read(drv, addr, 0, 12)
    except Exception as exc:
        print(f"[{tag}] \u2717  Read error: {exc}")
        return False

    magic = struct.unpack_from('<I', header, 0)[0]
    if magic != 0x69502d52:
        print(f"[{tag}] \u2717  Bad magic 0x{magic:08X} (expected 0x69502d52 'R-Pi') \u2014 blank or wrong chip?")
        return False

    eeplen = struct.unpack_from('<I', header, 8)[0]
    if eeplen < 12 or eeplen > capacity:
        print(f"[{tag}] \u2717  eeplen={eeplen} out of range (capacity={capacity})")
        return False

    # ── Read full image ────────────────────────────────────────────────────
    print(f"[{tag}] Reading {eeplen} bytes\u2026")
    try:
        data = eeprom_read(drv, addr, 0, eeplen)
    except Exception as exc:
        print(f"[{tag}] \u2717  Read error: {exc}")
        return False

    if output_path:
        output_path.write_bytes(data)
        print(f"[{tag}] Saved \u2192 {output_path}")

    # ── Dump atom info ─────────────────────────────────────────────────────
    numatoms = struct.unpack_from('<H', data, 6)[0]
    print(f"[{tag}] {numatoms} atom(s) found")

    for _, atype, _, payload in iter_atoms(data):
        if atype == VENDOR_ATOM_TYPE and len(payload) >= 22:
            uid   = uuid_mod.UUID(bytes=bytes(payload[0:16]))
            vslen = payload[20]
            pslen = payload[21]
            vstr  = payload[22         : 22 + vslen        ].rstrip(b'\x00').decode('utf-8', 'replace')
            pstr  = payload[22 + vslen : 22 + vslen + pslen].rstrip(b'\x00').decode('utf-8', 'replace')
            print(f"         Vendor  : {vstr}")
            print(f"         Product : {pstr}")
            print(f"         UUID    : {uid}")
        elif atype == SNUM_TYPE and payload[:4] == SNUM_MAGIC:
            serial = payload[4:].rstrip(b'\x00').decode('ascii', 'replace')
            print(f"         Serial  : {serial}")

    # ── Crypto verify ──────────────────────────────────────────────────────
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        verify_eeprom(tmp_path, public_key_path)
        return True
    except SystemExit:
        return False
    finally:
        os.unlink(tmp_path)


def readback_eeprom(
    public_key_path : Path,
    eeprom_model    : str,
    port            : str,
    output_path     : Path | None,
):
    """Read and verify a single connected EEPROM."""
    model_key = eeprom_model.lower().replace('-', '').replace(' ', '')
    if model_key not in EEPROM_MODELS:
        sys.exit(f"[readback] ERROR: Unknown EEPROM model '{eeprom_model}'.\n"
                 f"  Supported: {', '.join(EEPROM_MODELS)}")
    capacity, _ = EEPROM_MODELS[model_key]

    drv  = open_i2cdriver(port)
    print(f"[readback] Detecting EEPROM\u2026")
    addr = detect_eeprom(drv)
    if addr is None:
        sys.exit("[readback] ERROR: No EEPROM detected on 0x50\u20130x57.")
    print(f"[readback] Found EEPROM at 0x{addr:02X}")

    ok = _read_and_verify_one(drv, addr, capacity, public_key_path, output_path)
    if not ok:
        sys.exit("[readback] Failed.")


def batch_readback(
    public_key_path : Path,
    eeprom_model    : str,
    port            : str,
    output_dir      : Path | None,
    auto_detect     : bool,
):
    """
    Batch readback loop.

    auto_detect=True  : read immediately whenever a new EEPROM appears on the
                        bus; no keypress needed.  Useful on a pogo-pin fixture.
    auto_detect=False : prompt "Press Enter" before each read (default).
    """
    model_key = eeprom_model.lower().replace('-', '').replace(' ', '')
    if model_key not in EEPROM_MODELS:
        sys.exit(f"[batch-rb] ERROR: Unknown EEPROM model '{eeprom_model}'.\n"
                 f"  Supported: {', '.join(EEPROM_MODELS)}")
    capacity, _ = EEPROM_MODELS[model_key]

    drv = open_i2cdriver(port)

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"[batch-rb] Output dir  : {output_dir}")

    read_count    = 0
    ok_count      = 0
    board_present = detect_eeprom(drv) is not None  # something already there?

    print()
    print("=" * 60)
    if auto_detect:
        print("  Auto-detect mode — insert board to trigger read.")
    else:
        print("  Manual mode — press Enter to read each board.")
    print("  Ctrl+C to stop.")
    print("=" * 60)

    try:
        while True:
            if auto_detect:
                # If a board is already there, wait for removal first so we
                # don't immediately re-read the same chip.
                if board_present:
                    print(f"[batch-rb] Waiting for board removal\u2026",
                          end='\r', flush=True)
                    while detect_eeprom(drv) is not None:
                        time.sleep(0.1)
                    board_present = False
                    print(f"[batch-rb] Board removed.  "
                          f"Waiting for next insertion\u2026",
                          end='\r', flush=True)

                # Wait for a new insertion
                addr = None
                while addr is None:
                    addr = detect_eeprom(drv)
                    if addr is None:
                        time.sleep(0.1)
                board_present = True
                print()  # newline after \r
                print(f"[batch-rb] Board detected at 0x{addr:02X} \u2014 reading\u2026")

            else:
                # Manual mode: prompt, then detect
                print()
                print("  Connect board and press [Enter] to read "
                      "(Ctrl+C to quit)\u2026", end='', flush=True)
                try:
                    input()
                except EOFError:
                    pass

                addr = detect_eeprom(drv)
                if addr is None:
                    print("[batch-rb] \u2717  No EEPROM detected \u2014 check wiring and try again.")
                    continue
                print(f"[batch-rb] Found EEPROM at 0x{addr:02X}")

            # ── Read + verify ──────────────────────────────────────────────
            read_count += 1
            out_file = (output_dir / f"readback_{read_count:04d}.bin") if output_dir else None

            ok = _read_and_verify_one(
                drv, addr, capacity, public_key_path, out_file,
                tag=f"batch-rb/{read_count}",
            )
            result = "\u2713  OK" if ok else "\u2717  FAILED"
            print(f"[batch-rb] {result} \u2014 device {read_count}  "
                  f"(total: {ok_count + ok}/{read_count})")
            if ok:
                ok_count += 1

    except KeyboardInterrupt:
        print(f"\n\n[batch-rb] Stopped.  "
              f"{ok_count}/{read_count} device(s) verified OK.")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="RSA-PSS sign/verify/batch-flash HAT+ EEPROM binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a new 2048-bit key pair
  eeprom-sign keygen --private hat_private.pem --public hat_public.pem

  # Sign a single EEPROM image
  eeprom-sign sign eeprom_base.bin --serial BATCH0001 \\
      --private hat_private.pem --output eeprom_signed.bin

  # Pre-sign a batch of images
  eeprom-sign sign eeprom_base.bin --serial BATCH0000 \\
      --start 1 --stop 100 \\
      --private hat_private.pem --output-dir ./signed

  # Verify a signed EEPROM image
  eeprom-sign verify eeprom_signed.bin --public hat_public.pem

  # Strip the signature atom (e.g. before re-signing)
  eeprom-sign strip eeprom_signed.bin --output eeprom_stripped.bin

  # Batch flash: auto-increment serial, fresh UUID per board, 24C256 EEPROM
  eeprom-sign batch eeprom_base.bin \\
      --serial BATCH0001 \\
      --private hat_private.pem \\
      --public  hat_public.pem \\
      --eeprom  24c256 \\
      --port    /dev/ttyUSB0 \\
      --output-dir ./signed_images

  # Batch flash without saving files, skip crypto re-verify after flash
  eeprom-sign batch eeprom_base.bin \\
      --serial BATCH0001 --private hat_private.pem \\
      --eeprom 24c256 --port /dev/ttyUSB0 --no-verify

  # Batch flash with auto-detect (no Enter needed)
  eeprom-sign batch eeprom_base.bin \\
      --serial BATCH0001 --private hat_private.pem \\
      --eeprom 24c256 --port /dev/ttyUSB0 --auto-detect

  # Read back and verify a flashed EEPROM (saves a copy to readback.bin)
  eeprom-sign readback --public hat_public.pem \\
      --eeprom 24c256 --port /dev/tty.usbserial-I2CDRIVER --output readback.bin

  # Read back and verify without saving
  eeprom-sign readback --public hat_public.pem \\
      --eeprom 24c256 --port /dev/tty.usbserial-I2CDRIVER

  # Batch readback: press Enter for each board
  eeprom-sign batch-readback --public hat_public.pem \\
      --eeprom 24c256 --port /dev/tty.usbserial-I2CDRIVER

  # Batch readback: auto-trigger on board insertion
  eeprom-sign batch-readback --public hat_public.pem \\
      --eeprom 24c256 --port /dev/tty.usbserial-I2CDRIVER --auto-detect
""")
    sub = p.add_subparsers(dest='cmd', required=True)

    # ── keygen ────────────────────────────────────────────────────────────
    kg = sub.add_parser('keygen', help='Generate RSA key pair')
    kg.add_argument('--private', required=True, type=Path, metavar='FILE')
    kg.add_argument('--public',  required=True, type=Path, metavar='FILE')
    kg.add_argument('--bits',    type=int, default=2048,
                    choices=[2048, 3072, 4096], metavar='BITS')

    # ── sign ──────────────────────────────────────────────────────────────
    sg = sub.add_parser('sign', help='Sign one or a range of EEPROM binaries')
    sg.add_argument('input',        type=Path,
                    help='Base (unsigned) EEPROM .bin image')
    sg.add_argument('--serial',     required=True, metavar='STRING',
                    help='Serial number string, e.g. BATCH0001. '
                         'Used directly for single sign, or as the template '
                         'prefix+width when --start/--stop are given.')
    sg.add_argument('--private',    required=True, type=Path, metavar='FILE',
                    help='RSA private key PEM file')
    sg.add_argument('--output',     type=Path, default=None, metavar='FILE',
                    help='Output path for signed binary (single sign only)')
    sg.add_argument('--start',      type=int,  default=None, metavar='N',
                    help='First serial number in batch (integer)')
    sg.add_argument('--stop',       type=int,  default=None, metavar='N',
                    help='Last serial number in batch (integer, inclusive)')
    sg.add_argument('--output-dir', type=Path, default=None, metavar='DIR',
                    help='Output directory for batch signing '
                         '(default: current directory)')

    # ── verify ────────────────────────────────────────────────────────────
    vf = sub.add_parser('verify', help='Verify a signed EEPROM binary')
    vf.add_argument('input',    type=Path)
    vf.add_argument('--public', required=True, type=Path, metavar='FILE')

    # ── strip ─────────────────────────────────────────────────────────────
    st = sub.add_parser('strip', help='Remove the RSIG signature atom')
    st.add_argument('input',    type=Path)
    st.add_argument('--output', required=True, type=Path, metavar='FILE')

    # ── batch ─────────────────────────────────────────────────────────────
    bt = sub.add_parser(
        'batch',
        help='Interactive batch sign+flash loop via I2CDriver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Sign a fresh image (new UUID, incremented serial) and flash it\n"
            "to a 24Cxxx EEPROM via I2CDriver for each board in sequence.\n"
            "Press Enter to advance to the next board; Ctrl+C to stop."
        ),
    )
    bt.add_argument('input',
                    type=Path,
                    help='Base (unsigned) EEPROM .bin image')
    bt.add_argument('--serial',  required=True,
                    metavar='STRING',
                    help='Starting serial, e.g. BATCH0001 '
                         '(trailing digits are incremented per board)')
    bt.add_argument('--private', required=True, type=Path, metavar='FILE',
                    help='RSA private key PEM file')
    bt.add_argument('--public',  type=Path, default=None, metavar='FILE',
                    help='RSA public key PEM file (for in-memory crypto verify after flash)')
    bt.add_argument('--eeprom',
                    default='24c256',
                    metavar='MODEL',
                    help=f'EEPROM model (default: 24c256). '
                         f'Supported: {", ".join(EEPROM_MODELS)}')
    bt.add_argument('--port',
                    default='/dev/ttyUSB0',
                    metavar='PORT',
                    help='Serial port for I2CDriver (default: /dev/ttyUSB0). '
                         'Windows example: COM3')
    bt.add_argument('--output-dir',
                    type=Path, default=None, metavar='DIR',
                    help='Directory to save each signed .bin (optional)')
    bt.add_argument('--no-verify',
                    action='store_true',
                    help='Skip the post-flash crypto signature verification')
    bt.add_argument('--auto-detect',
                    action='store_true',
                    help='Flash automatically on board insertion (no Enter needed)')

    # ── readback ──────────────────────────────────────────────────────────
    rb = sub.add_parser('readback', help='Read a flashed EEPROM and verify its signature')
    rb.add_argument('--public',  required=True, type=Path, metavar='FILE',
                    help='RSA public key PEM file')
    rb.add_argument('--eeprom',  default='24c256', metavar='MODEL',
                    help=f'EEPROM model (default: 24c256). '
                         f'Supported: {", ".join(EEPROM_MODELS)}')
    rb.add_argument('--port',    default='/dev/ttyUSB0', metavar='PORT',
                    help='Serial port for I2CDriver (default: /dev/ttyUSB0)')
    rb.add_argument('--output',  type=Path, default=None, metavar='FILE',
                    help='Optional path to save the raw binary read from the chip')

    # ── batch-readback ────────────────────────────────────────────────────
    brb = sub.add_parser(
        'batch-readback',
        help='Batch read+verify loop via I2CDriver',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Read and verify multiple EEPROMs in sequence.\n"
            "Use --auto-detect to trigger on board insertion, or press\n"
            "Enter manually for each board."
        ),
    )
    brb.add_argument('--public',      required=True, type=Path, metavar='FILE',
                     help='RSA public key PEM file')
    brb.add_argument('--eeprom',      default='24c256', metavar='MODEL',
                     help=f'EEPROM model (default: 24c256). '
                          f'Supported: {", ".join(EEPROM_MODELS)}')
    brb.add_argument('--port',        default='/dev/ttyUSB0', metavar='PORT',
                     help='Serial port for I2CDriver (default: /dev/ttyUSB0)')
    brb.add_argument('--output-dir',  type=Path, default=None, metavar='DIR',
                     help='Directory to save each readback .bin (optional)')
    brb.add_argument('--auto-detect', action='store_true',
                     help='Read automatically on board insertion (no Enter needed)')


    args = p.parse_args()

    if args.cmd == 'keygen':
        generate_keypair(args.private, args.public, args.bits)

    elif args.cmd == 'sign':
        if args.start is not None or args.stop is not None:
            # Batch mode
            if args.start is None or args.stop is None:
                p.error("sign: --start and --stop must both be provided for batch signing")
            try:
                prefix, digits_str, _ = parse_serial(args.serial)
            except ValueError as e:
                p.error(f"sign: {e}")
            digit_width = len(digits_str)
            if args.start > args.stop:
                p.error(f"sign: --start ({args.start}) must be <= --stop ({args.stop})")

            base_data = bytearray(args.input.read_bytes())
            if has_sig_atom(base_data):
                base_data = strip_atom(base_data, 0x0004, MAGIC)
            base_data = strip_snum_atom(base_data)
            private_key = load_private_key(args.private)
            output_dir  = args.output_dir or Path('.')
            output_dir.mkdir(parents=True, exist_ok=True)
            count = args.stop - args.start + 1

            print(f"[sign] Base image  : {args.input}  ({count_atoms(base_data)} atoms)")
            print(f"[sign] Serial range: "
                  f"{format_serial(prefix, digit_width, args.start)} → "
                  f"{format_serial(prefix, digit_width, args.stop)}  ({count} images)")
            print(f"[sign] Output dir  : {output_dir}")
            print()

            for i, value in enumerate(range(args.start, args.stop + 1)):
                serial     = format_serial(prefix, digit_width, value)
                out_path   = output_dir / f"{serial}.bin"
                final_image = _sign_image(bytes(base_data), private_key, serial)
                out_path.write_bytes(final_image)
                print(f"  [{i+1:>{len(str(count))}}/{count}]  {serial}  →  {out_path.name}")

            print()
            print(f"[sign] Done — {count} signed image(s) in {output_dir}/")
        else:
            # Single mode
            if args.output is None:
                p.error("sign: --output is required when not using --start/--stop")
            sign_eeprom(args.input, args.output, args.private, args.serial)

    elif args.cmd == 'verify':
        verify_eeprom(args.input, args.public)

    elif args.cmd == 'strip':
        strip_eeprom(args.input, args.output)

    elif args.cmd == 'batch':
        batch_flash(
            input_path      = args.input,
            private_key_path= args.private,
            public_key_path = args.public,
            serial_start    = args.serial,
            eeprom_model    = args.eeprom,
            port            = args.port,
            output_dir      = args.output_dir,
            no_verify       = args.no_verify,
            auto_detect     = args.auto_detect,
        )

    elif args.cmd == 'readback':
        readback_eeprom(
            public_key_path = args.public,
            eeprom_model    = args.eeprom,
            port            = args.port,
            output_path     = args.output,
        )

    elif args.cmd == 'batch-readback':
        batch_readback(
            public_key_path = args.public,
            eeprom_model    = args.eeprom,
            port            = args.port,
            output_dir      = args.output_dir,
            auto_detect     = args.auto_detect,
        )

def cli():
    main()

if __name__ == '__main__':
    main()
