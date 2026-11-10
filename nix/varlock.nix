# Wraps varlock so that each varlock command gets the secrets of a trusted
# project from sefko, through `sefko exec --if-trusted`. The wrapper looks for
# sefko on PATH when it starts, so it does not depend on sefko: without sefko,
# with a sefko that has no --if-trusted, or in a project that is not trusted,
# it runs varlock unchanged. That makes it safe to put in a shared dev shell.
{ lib
, symlinkJoin
, writeShellScript
, gnugrep
}:

{ package
, program ? "varlock"
}:

let
  real = lib.escapeShellArg "${package}/bin/${program}";
  script = writeShellScript "${program}-sefko" ''
    if command -v sefko >/dev/null 2>&1 && sefko exec --help 2>/dev/null | ${lib.getExe gnugrep} -q -- --if-trusted; then
      exec sefko exec --if-trusted -- ${real} "$@"
    fi
    exec ${real} "$@"
  '';
in
symlinkJoin {
  name = "${program}-sefko-${package.version or "unversioned"}";
  paths = [ package ];
  postBuild = ''
    rm "$out/bin/${program}"
    ln -s ${script} "$out/bin/${program}"
  '';
  meta = (package.meta or { }) // {
    description = "${program} with the secrets of trusted projects from sefko";
    mainProgram = program;
  };
}
