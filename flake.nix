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
      url = "github:logos-co/logos-evm-keystore-module/e4c6fcd39411f0ed52083f0a7fb2701e742f81f1";
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
