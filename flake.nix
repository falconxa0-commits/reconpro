# ReconPro Nix flake.
#
# NOTE (honest): no nix binary exists in the build sandbox, so this flake
# was never evaluated here (`nix build` / `nix flake check` untested).
# default.nix carries the same caveat.
{
  description = "ReconPro v11 — Enterprise Security Reconnaissance Platform (pure Python)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        reconpro = pkgs.python3Packages.callPackage ./default.nix {
          src = self;
        };
      in
      {
        packages = {
          inherit reconpro;
          default = reconpro;
        };

        apps.reconpro = {
          type = "app";
          program = "${reconpro}/bin/reconpro";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (
              ps: with ps; [
                rich
                textual
                requests
                pytest
                pytest-cov
              ]
            ))
          ];
          shellHook = ''
            echo "ReconPro dev shell — run: reconpro --version"
          '';
        };
      }
    );
}
