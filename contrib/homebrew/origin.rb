class Origin < Formula
  desc "Cryptographic provenance for digital artifacts"
  homepage "https://github.com/thupa-pro/Origin"
  license "MIT"

  stable do
    url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.1.1.tar.gz"
    sha256 "da3cd68eb51cb9e1d94ceb61b471599fe798258de7b3e76b9263f6b384ae3bda"

    resource "origin-core" do
      url "https://github.com/thupa-pro/Origin/archive/refs/tags/v1.1.1.tar.gz"
      sha256 "da3cd68eb51cb9e1d94ceb61b471599fe798258de7b3e76b9263f6b384ae3bda"
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
