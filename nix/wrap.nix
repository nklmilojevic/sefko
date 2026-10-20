# Wraps a CLI so it gets its token from sefko through `sefko wrap`. The result
# keeps everything else in the package (man pages, completions) and replaces
# only the program.
{ lib
, symlinkJoin
, makeWrapper
, sefko
}:

{ package
, secret
, program ? package.meta.mainProgram or package.pname
, var ? null
, bypassEnv ? [ ]
, retry ? true
}:

let
  args = [ "wrap" secret ]
    ++ lib.optionals (var != null) [ "--var" var ]
    ++ lib.concatMap (v: [ "--bypass" v ]) bypassEnv
    ++ lib.optional (!retry) "--no-retry"
    ++ [ "--" "${package}/bin/${program}" ];
in
symlinkJoin {
  name = "${program}-sefko-${package.version or "unversioned"}";
  paths = [ package ];
  nativeBuildInputs = [ makeWrapper ];
  postBuild = ''
    rm "$out/bin/${program}"
    makeWrapper ${lib.getExe sefko} "$out/bin/${program}" \
      --add-flags ${lib.escapeShellArg (lib.escapeShellArgs args)}
  '';
  meta = (package.meta or { }) // {
    description = "${program} with its token from sefko";
    mainProgram = program;
  };
}
