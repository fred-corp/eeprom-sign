# Formula for the Homebrew tap: fred-corp/tap
# Repo: https://github.com/fred-corp/homebrew-tap
#
# Installation:
#   brew tap fred-corp/tap
#   brew install eeprom-sign
#
# After each release, update `url`, `sha256`, and `version` below.
# The SHA256 is printed by the GitHub Actions release workflow.

class EepromSign < Formula
  desc     "RSA-PSS sign, verify, and batch-flash Raspberry Pi HAT+ EEPROMs"
  homepage "https://github.com/fred-corp/eeprom-sign"
  version  "0.1.0"

  # ── macOS binary (built by CI, attached to the GitHub release) ───────────
  on_macos do
    if Hardware::CPU.arm?
      # Apple Silicon — build separately in CI if needed, or use the x86_64
      # binary under Rosetta by falling through to the Intel block.
      url "https://github.com/fred-corp/eeprom-sign/releases/download/v#{version}/eeprom-sign-macos-arm64"
      sha256 "REPLACE_WITH_ARM64_SHA256_FROM_CI"
    else
      url "https://github.com/fred-corp/eeprom-sign/releases/download/v#{version}/eeprom-sign-macos-x86_64"
      sha256 "REPLACE_WITH_X86_64_SHA256_FROM_CI"
    end
  end

  # No build step — we ship a pre-built PyInstaller binary.
  def install
    bin.install "eeprom-sign"
  end

  test do
    assert_match "usage", shell_output("#{bin}/eeprom-sign --help")
  end
end
