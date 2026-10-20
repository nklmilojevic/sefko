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

  wrapperType = types.submodule ({ name, ... }: {
    options = {
      package = mkOption {
        type = types.package;
        description = "Package whose program gets the secret.";
      };
      program = mkOption {
        type = types.str;
        default = name;
        description = "Program in the package's bin directory to wrap.";
      };
      secret = mkOption {
        type = types.str;
        description = "Alias in `programs.sefko.secrets` that holds the token.";
      };
      var = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Variable that carries the token. Defaults to the secret's `env`.";
      };
      bypassEnv = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "More variables that, when set, make the wrapper run the program without sefko.";
      };
      retry = mkOption {
        type = types.bool;
        default = true;
        description = "Run the program again after a rejected token is refreshed. Turn off for programs that are not safe to run twice.";
      };
    };
  });

  wrap = pkgs.callPackage ./wrap.nix { sefko = cfg.package; };

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

    wrappers = mkOption {
      type = types.attrsOf wrapperType;
      default = { };
      example = lib.literalExpression ''
        {
          gh = { package = pkgs.gh; secret = "github"; bypassEnv = [ "GITHUB_TOKEN" ]; };
          glab = { package = pkgs.glab; secret = "gitlab"; };
        }
      '';
      description = ''
        Programs that get a token from sefko through `sefko wrap`, keyed by
        program name. Each one is installed with a higher priority than an
        unwrapped copy of the same package.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isDarwin;
        message = "programs.sefko only supports macOS for now.";
      }
    ] ++ lib.concatLists (lib.mapAttrsToList
      (name: w: [
        {
          assertion = cfg.secrets ? ${w.secret};
          message = "programs.sefko.wrappers.${name}: secret \"${w.secret}\" is not in programs.sefko.secrets.";
        }
        {
          assertion = w.var != null || (cfg.secrets.${w.secret}.env or null) != null;
          message = "programs.sefko.wrappers.${name}: set var, or env on secret \"${w.secret}\".";
        }
      ])
      cfg.wrappers);

    home.packages = [ cfg.package ]
      ++ lib.mapAttrsToList (_: w: lib.hiPrio (wrap { inherit (w) package program secret var bypassEnv retry; })) cfg.wrappers;

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

    # No reload hook on activation: the plist only changes with the binary, so a
    # config-only switch keeps the agent and its cache, and the agent re-reads
    # the config file on its own within seconds. A SIGHUP sent here could also
    # reach an agent launchd has only just started, before it handles signals.
  };
}
