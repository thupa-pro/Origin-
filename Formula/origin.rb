class Origin < Formula
  desc "Cryptographic provenance for digital artifacts"
  homepage "https://github.com/thupa-pro/Origin"
  url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.2.0.tar.gz"
  sha256 "2391b7c2ec73ddb3b8e926e3e425f1038dc34cef9b0449fb6310a1fa001e171f"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "origin-cli")
  end

  test do
    system "#{bin}/origin", "--version"
  end
end
