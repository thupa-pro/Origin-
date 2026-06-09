class Origin < Formula
  desc "Cryptographic provenance for digital artifacts"
  homepage "https://github.com/thupa-pro/Origin"
  license "MIT"

  stable do
    url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.1.0.tar.gz"
    sha256 "291271c36c0ecf4d15efa505933031fa07abcca474a67b58cdfcc5fb8207c61d"

    resource "origin-core" do
      url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.1.0.tar.gz"
      sha256 "291271c36c0ecf4d15efa505933031fa07abcca474a67b58cdfcc5fb8207c61d"
    end
  end

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "origin-cli")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/origin --version")
    system bin/"origin", "keygen"
    assert_predicate testpath/"origin-public.key", :exist?
  end
end
