{
  description = "Origin Network — hermetic development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo-deny
            cargo-fuzz
            wasm-pack
            nodejs
            pnpm
            python3
            foundry-bin
            tilt
            kind
            kubectl
            helm-docs
            talisman
            gitleaks
            actionlint
          ];

          shellHook = ''
            echo "═══════════════════════════════════════════════"
            echo "  Origin Network — Hermetic Dev Shell"
            echo "  Rust:  $(rustc --version)"
            echo "  Node:  $(node --version)"
            echo "  Nix:   $(nix --version)"
            echo "═══════════════════════════════════════════════"
            echo "  Run 'cargo build' to compile all crates"
            echo "  Run 'cargo test'  to run all tests"
            echo "═══════════════════════════════════════════════"
          '';
        };
      }
    );
}
