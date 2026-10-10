{
  description = "manager_probe — doc-test fixture: the keystore's custodian, a requester and the approver, in one headless module.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module/e4c6fcd39411f0ed52083f0a7fb2701e742f81f1";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
      inputs.keystore_module.follows = "keystore_module";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
