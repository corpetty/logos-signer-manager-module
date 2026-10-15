{
  description = "Logos signer manager: takes signature requests and has each account's signer sign. Holds no keys.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # The signer interface's contract, bound at runtime to each signer module by name.
    logos-signer-interface = {
      url = "github:logos-co/logos-signer-interface/d2f95e01b8c2aa1c1e1ed2c7cf18e7963a685d02";
      flake = false;
    };
    # The first signer: the key files. A dependency, so it loads with the manager.
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/c68b7b4d933f30f87e033e6a1d7865f298e4d858";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    # The Keycard signers: optional, so they load with the manager only where installed.
    # Only their contracts are consumed.
    keycard_module = {
      url = "github:logos-co/logos-keycard-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    keycard_shell_module = {
      url = "github:logos-co/logos-keycard-shell-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    # The QR signer, optional too. Pinned to the module's first branch until it reaches main.
    qr_signer_module = {
      url = "github:logos-co/logos-qr-signer-module/62616c7924a25e596c87d5bb1beee7bfbece28a8";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross target the builder understands, never a host.
      targets = systems ++ [ "x86_64-windows" ];
      forAllTargets = f: nixpkgs.lib.genAttrs targets f;
    in
    {
      packages = forAllTargets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
