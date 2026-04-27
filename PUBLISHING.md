# Publishing guide

How to publish `eeprom-sign` to PyPI and make it installable via Homebrew.

---

## Project layout

```txt
eeprom-sign/                   ← main repo (this one)
├── src/
│   └── eeprom_sign/
│       └── __init__.py        ← the tool
├── pyproject.toml
├── README.md
├── LICENSE
├── eeprom-sign.rb             ← copy this file to your tap repo after each release
└── .github/
    └── workflows/
        └── release.yml        ← CI: publish to PyPI + build macOS binary

homebrew-tap/                  ← separate repo: github.com/yourname/homebrew-tap
└── Formula/
    └── eeprom-sign.rb
```

---

## One-time setup

### 1. Create the GitHub repos

- `github.com/fred-corp/eeprom-sign` — the main tool repo (this code).
- `github.com/fred-corp/homebrew-tap` — the Homebrew tap.
  Must be named exactly `homebrew-tap` for `brew tap fred-corp/tap` to work.
  Create it with a `Formula/` directory and commit the `.rb` file there.

### 2. Configure PyPI trusted publishing (no API token needed)

1. Create an account at [https://pypi.org](https://pypi.org) and reserve the `eeprom-sign` name
   by uploading once manually (see "First manual upload" below).
2. Go to **PyPI → your account → Publishing → Add a new publisher**.
3. Fill in:
   - GitHub owner: `Fred Corp.`
   - Repository: `eeprom-sign`
   - Workflow: `release.yml`
   - Environment: `pypi` (or leave blank)
4. That's it — the CI workflow uses OIDC and needs no secret token.

### 3. First manual upload (reserves the PyPI name)

```bash
pip install hatch

cd eeprom-sign/
hatch build              # creates dist/eeprom_sign-0.1.0.tar.gz and .whl

pip install twine
twine upload dist/*      # prompts for PyPI username/password once
```

After this, all future releases are handled by CI.

---

## Releasing a new version

### Step 1 — Bump the version

Edit `pyproject.toml`:

```toml
version = "0.2.0"
```

Commit and push to `main`.

### Step 2 — Tag the release

```bash
git tag v0.2.0
git push origin v0.2.0
```

This triggers the `release.yml` workflow which:

- Builds the wheel and sdist and publishes them to PyPI.
- Builds a standalone macOS binary with PyInstaller.
- Attaches the binary and its SHA-256 checksum to the GitHub release.

### Step 3 — Update the Homebrew formula

1. Copy `eeprom-sign.rb` from this repo into your tap repo at
   `Formula/eeprom-sign.rb`.
2. Replace the `sha256` values with the ones printed by CI
   (find them in the GitHub release assets: `eeprom-sign.sha256`).
3. Update `version` to match.
4. Commit and push to `homebrew-tap`.

```bash
cd homebrew-tap/
cp ../eeprom-sign/eeprom-sign.rb Formula/eeprom-sign.rb
# edit sha256 and version
git add Formula/eeprom-sign.rb
git commit -m "eeprom-sign 0.2.0"
git push
```

---

## Installation methods (for your users)

### pip (cross-platform)

```bash
pip install eeprom-sign
eeprom-sign --help
```

### Homebrew (macOS, no Python needed)

```bash
brew tap yourname/tap
brew install eeprom-sign
eeprom-sign --help
```

### From source

```bash
git clone https://github.com/yourname/eeprom-sign.git
cd eeprom-sign
pip install -e .
eeprom-sign --help
```

---

## Building the macOS binary locally (optional)

If you want to test the PyInstaller binary before pushing a tag:

```bash
pip install pyinstaller cryptography i2cdriver
pyinstaller --onefile --name eeprom-sign --strip src/eeprom_sign/__init__.py
./dist/eeprom-sign --help
```

The binary in `dist/` is fully self-contained — no Python installation
required on the target machine.

To support both Apple Silicon and Intel as separate downloads, run the
`pyinstaller` step on each architecture (either natively or in CI using
`macos-latest` for x86_64 and `macos-14` for arm64) and upload both to
the GitHub release. Update the Homebrew formula with both SHA-256 values.
