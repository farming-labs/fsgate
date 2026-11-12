{
  description = "Development shells for fsgate, with the tools CI pins";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # nixpkgs has one stable rustc; this has every release and dated nightly.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forEachSystem =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );
    in
    {
      # .github/nix/check-pins.sh fails CI when a version here differs from
      # the one a workflow pins.
      devShells = forEachSystem (pkgs: {
        # CI's `stable` is the current release; this one is the release when
        # flake.lock was last updated.
        default = pkgs.mkShell {
          packages = [
            (pkgs.rust-bin.stable.latest.minimal.override {
              extensions = [
                "rustfmt"
                "clippy"
              ];
            })
            pkgs.cargo-mutants
            pkgs.actionlint
            pkgs.zizmor
            pkgs.shellcheck
          ];
        };
        # ci.yml's `msrv` job, and `rust-version` in Cargo.toml.
        msrv = pkgs.mkShell {
          packages = [ pkgs.rust-bin.stable."1.85.0".minimal ];
        };
        # fuzz.yml.
        fuzz = pkgs.mkShell {
          packages = [
            pkgs.rust-bin.nightly."2026-11-08".minimal
            pkgs.cargo-fuzz
          ];
        };
      });
    };
}
