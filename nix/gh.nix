# gh whose token comes from sefko. See nix/wrap.nix.
{ gh
, sefkoWrap
}:

sefkoWrap {
  package = gh;
  secret = "github";
  bypassEnv = [ "GH_TOKEN" "GITHUB_TOKEN" ];
}
