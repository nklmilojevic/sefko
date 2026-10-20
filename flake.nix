{
  description = "sefko - keeps allowlisted 1Password secrets in memory and serves them over a Unix socket";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    home-manager = {
      url = "github:nix-community/home-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, home-manager }:
    let
      inherit (nixpkgs) lib;

      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      overlay = final: prev: {
        sefko = final.callPackage ./package.nix {
          version = self.shortRev or self.dirtyShortRev or "dev";
        };
        gh-sefko = final.callPackage ./nix/gh.nix { };
      };

      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ overlay ];
            }
          )
        );
    in
    {
      overlays.default = overlay;

      homeManagerModules.default = import ./nix/hm-module.nix { inherit self; };

      packages = forAllSystems (pkgs: {
        default = pkgs.sefko;
        sefko = pkgs.sefko;
        gh = pkgs.gh-sefko;
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = lib.getExe pkgs.sefko;
        };
      });

      checks = forAllSystems (pkgs: {
        sefko = pkgs.sefko;
        gh = pkgs.gh-sefko;
        hm-module = import ./nix/tests/hm-module.nix { inherit pkgs self home-manager; };
      });

      # Every development tool comes from here; `just` lists the tasks.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            golangci-lint
            gotestsum
            just
            nixpkgs-fmt
            shellcheck
            git
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
