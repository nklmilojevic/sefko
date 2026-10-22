{ lib
, stdenv
, buildGoModule
, installShellFiles
, version
,
}:

buildGoModule {
  pname = "sefko";
  inherit version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./cmd
      ./internal
    ];
  };

  vendorHash = "sha256-UdTgPKmmOzLP7hRRHffKO+HdO7LViTh/MQ81bku1Odg=";

  env.CGO_ENABLED = "1";

  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd sefko \
      --bash <($out/bin/sefko completion bash) \
      --fish <($out/bin/sefko completion fish) \
      --zsh <($out/bin/sefko completion zsh)
  '';

  meta = {
    description = "Per-user agent that keeps allowlisted 1Password secrets in memory and serves them over a Unix socket";
    homepage = "https://github.com/nklmilojevic/sefko";
    license = lib.licenses.mit;
    platforms = lib.platforms.darwin;
    mainProgram = "sefko";
  };
}
