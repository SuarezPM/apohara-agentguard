# Homebrew formula TEMPLATE for apohara-agentguard.
#
# Copy this file into a tap as Formula/apohara-agentguard.rb, then fill the
# four TODO-HUMAN sha256 placeholders from the release's SHA256SUMS asset and
# bump `version` on each release. Step-by-step: packaging/homebrew/README.md.
class ApoharaAgentguard < Formula
  desc "Deterministic, offline safety hook + seccomp/Landlock sandbox + input firewall for AI coding agents"
  homepage "https://github.com/SuarezPM/apohara-agentguard"
  version "0.5.2"
  license "MIT OR Apache-2.0"

  # Release assets are bare per-triple binaries (no archive, no bottles), so
  # every platform/arch pair pins its own URL + checksum. Linux ships the
  # *musl* static builds: they avoid glibc-version coupling across the many
  # distros Homebrew may run under.
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SuarezPM/apohara-agentguard/releases/download/v#{version}/apohara-agentguard-aarch64-apple-darwin"
      sha256 "TODO-HUMAN-SHA256-aarch64-apple-darwin" # matching line in the release SHA256SUMS
    else
      url "https://github.com/SuarezPM/apohara-agentguard/releases/download/v#{version}/apohara-agentguard-x86_64-apple-darwin"
      sha256 "TODO-HUMAN-SHA256-x86_64-apple-darwin" # matching line in the release SHA256SUMS
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/SuarezPM/apohara-agentguard/releases/download/v#{version}/apohara-agentguard-aarch64-unknown-linux-musl"
      sha256 "TODO-HUMAN-SHA256-aarch64-unknown-linux-musl" # matching line in the release SHA256SUMS
    elsif Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/SuarezPM/apohara-agentguard/releases/download/v#{version}/apohara-agentguard-x86_64-unknown-linux-musl"
      sha256 "TODO-HUMAN-SHA256-x86_64-unknown-linux-musl" # matching line in the release SHA256SUMS
    end
  end

  def install
    # The staged download keeps its release basename; rename to the canonical
    # command name when installing.
    binary = Dir["apohara-agentguard-*"].first
    odie "downloaded apohara-agentguard binary not found in staging" if binary.nil?

    sbin.install binary => "apohara-agentguard"
  end

  test do
    assert_match version.to_s, shell_output("#{sbin}/apohara-agentguard version")
  end
end
