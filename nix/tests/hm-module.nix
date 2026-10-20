# Evaluates the Home Manager module with a sample config and checks what it
# renders.
{ pkgs, self, home-manager }:

let
  hm = home-manager.lib.homeManagerConfiguration {
    inherit pkgs;
    modules = [
      self.homeManagerModules.default
      {
        home.username = "test";
        home.homeDirectory = "/Users/test";
        home.stateVersion = "26.05";
        programs.sefko = {
          enable = true;
          # Avoid evaluating the unfree 1Password CLI in CI.
          opPackage = pkgs.writeShellScriptBin "op" "exit 1";
          secrets.github = {
            ref = "op://Private/GitHub Personal Access Token/token";
            account = "my.1password.eu";
            env = "GH_TOKEN";
            validate.url = "https://api.github.com/user";
          };
          secrets.restic = {
            ref = "op://Private/restic/password";
            account = "my.1password.eu";
          };
        };
      }
    ];
  };
  cfg = hm.config;
  args = cfg.launchd.agents.sefko.config.ProgramArguments;
  expectedArgs = [
    "${pkgs.lib.getExe cfg.programs.sefko.package}"
    "agent"
    "--config"
    "/Users/test/.config/sefko/config.toml"
    "--socket"
    "/Users/test/.local/state/sefko/agent.sock"
  ];
in
assert pkgs.lib.assertMsg (args == expectedArgs) "unexpected ProgramArguments: ${builtins.toJSON args}";
assert pkgs.lib.assertMsg cfg.launchd.agents.sefko.enable "launchd agent not enabled";
assert pkgs.lib.assertMsg (!(cfg.home.activation ? sefkoReload)) "activation must not signal the agent";
pkgs.runCommand "sefko-hm-module-check" { nativeBuildInputs = [ pkgs.diffutils ]; } ''
  grep -q '^op_path = "/nix/store/.*/bin/op"$' ${cfg.xdg.configFile."sefko/config.toml".source}
  grep -v '^op_path' ${cfg.xdg.configFile."sefko/config.toml".source} > got.toml
  diff -u ${./config.golden.toml} got.toml
  touch $out
''
