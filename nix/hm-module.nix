{ self }:
{ config
, lib
, pkgs
, ...
}:

let
  inherit (lib) mkEnableOption mkIf mkOption types;

  cfg = config.programs.sefko;
  toml = pkgs.formats.toml { };
  label = "org.nix-community.home.sefko";
  configPath = "${config.xdg.configHome}/sefko/config.toml";
  socketPath = "${config.home.homeDirectory}/.local/state/sefko/agent.sock";

  validateType = types.submodule {
    options = {
      url = mkOption {
        type = types.str;
        description = "URL fetched with the secret to check that it still works.";
      };
      header = mkOption {
        type = types.str;
        default = "Authorization";
        description = "Header that carries the secret.";
      };
      format = mkOption {
        type = types.str;
        default = "Bearer {}";
        description = "Header value; {} is replaced by the secret.";
      };
    };
  };

  secretType = types.submodule {
    options = {
      ref = mkOption {
        type = types.strMatching "op://.+";
        description = "1Password secret reference.";
      };
      account = mkOption {
        type = types.str;
        description = "1Password account (sign-in address or ID).";
      };
      env = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Default variable name for `sefko exec` and `sefko env`.";
      };
      validate = mkOption {
        type = types.nullOr validateType;
        default = null;
        description = "Optional validator used by `sefko validate`.";
      };
    };
  };

  settings = {
    op_path = lib.getExe' cfg.opPackage "op";
    ttl = cfg.ttl;
    fetch_timeout = cfg.fetchTimeout;
    secrets = lib.mapAttrs (_: s: lib.filterAttrs (_: v: v != null) s) cfg.secrets;
  };
in
{
  options.programs.sefko = {
    enable = mkEnableOption "sefko, an in-memory agent for 1Password secrets";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "sefko.packages.\${system}.default";
      description = "The sefko package.";
    };

    opPackage = mkOption {
      type = types.package;
      default = pkgs._1password-cli;
      defaultText = lib.literalExpression "pkgs._1password-cli";
      description = "Package providing the `op` binary the agent runs.";
    };

    ttl = mkOption {
      type = types.str;
      default = "168h";
      description = "How long a fetched secret stays cached, from fetch time.";
    };

    fetchTimeout = mkOption {
      type = types.str;
      default = "60s";
      description = "How long to wait for 1Password approval.";
    };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = "Allowlisted secrets, keyed by alias.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isDarwin;
        message = "programs.sefko only supports macOS for now.";
      }
    ];

    home.packages = [ cfg.package ];

    xdg.configFile."sefko/config.toml".source = toml.generate "sefko-config.toml" settings;

    launchd.agents.sefko = {
      enable = true;
      config = {
        ProgramArguments = [
          (lib.getExe cfg.package)
          "agent"
          "--config"
          configPath
          "--socket"
          socketPath
        ];
        RunAtLoad = true;
        KeepAlive.SuccessfulExit = false;
        ProcessType = "Interactive";
      };
    };

    # The plist only changes with the binary, so a config-only switch keeps the
    # agent (and its cache) running; tell it to re-read the config.
    home.activation.sefkoReload = lib.hm.dag.entryAfter [ "setupLaunchAgents" ] ''
      run /bin/launchctl kill HUP "gui/$(/usr/bin/id -u)/${label}" 2>/dev/null || true
    '';
  };
}
