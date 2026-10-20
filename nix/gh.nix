# gh whose token comes from sefko. See nix/gh-wrapper.sh.
{ lib
, symlinkJoin
, gh
, sefko
, runtimeShell
}:

symlinkJoin {
  name = "gh-sefko-${gh.version}";
  paths = [ gh ];
  postBuild = ''
    rm "$out/bin/gh"
    substitute ${./gh-wrapper.sh} "$out/bin/gh" \
      --replace-fail "#!/bin/sh" "#!${runtimeShell}" \
      --replace-fail "@gh@" "${lib.getExe gh}" \
      --replace-fail "@sefko@" "${lib.getExe sefko}"
    chmod +x "$out/bin/gh"
  '';
  meta = gh.meta // {
    description = "gh with GH_TOKEN from sefko";
    mainProgram = "gh";
  };
}
