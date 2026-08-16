{
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      perSystem =
        {
          system,
          ...
        }:
        let
          pkgs = import inputs.nixpkgs {
            overlays = [ inputs.rust-overlay.overlays.default ];
            inherit system;
          };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./toolchain.toml;
          gitRev = self.rev or self.dirtyRev or "unknown";
        in
        {
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              rust-analyzer-unwrapped
              toolchain
              sqlite

              wrk # for benchmarking
              hey # for benchmarking
              imagemagick
            ];
            RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
          };

          packages.default = pkgs.stdenv.mkDerivation {
            pname = "webber";
            version = "0.1.0";

            src = ./.;

            nativeBuildInputs = with pkgs; [
              toolchain
              
              removeReferencesTo
            ];
            buildInputs = with pkgs; [
              sqlite
            ];

            WEBBER_GIT_REV = gitRev;

            buildPhase = ''
              runHook preBuild
              cargo build --release --offline 
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall

              install -Dm755 target/release/webber "$out/bin/webber"

              runHook postInstall
            '';
            postFixup = ''
              remove-references-to -t ${toolchain} "$out/bin/webber"
            '';            
          };
          apps.deploy = {
            type = "app";
            program = toString (
              pkgs.writeShellScript "deploy-webber" ''
                set -euo pipefail

                git add *.rs *.nix Cargo.toml toolchain.toml templates/* assets/*   

                copy_user="penger"
                deploy_user="webber-deployer"
                server="nuc"
  
                package="$(
                  nix build .#default --no-link --print-out-paths
                )"

                echo "Copying $package to $copy_user@$server"
                nix copy --to "ssh://$copy_user@$server" "$package"

                echo "Deploying on $server"
                ssh "$deploy_user@$server" sudo -n /run/current-system/sw/bin/deploy-webber "$package/bin/webber"
              ''
            );
          };
        };
    };
}
