class Origin < Formula
  desc "Cryptographic provenance for digital artifacts"
  homepage "https://github.com/thupa-pro/Origin"
  license "MIT"

  stable do
    url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.1.1.tar.gz"
    sha256 "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"

    resource "origin-core" do
      url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.1.1.tar.gz"
      sha256 "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
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
