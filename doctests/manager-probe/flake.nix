{
  description = "manager_probe — doc-test fixture: the keystore's custodian, a requester and the approver, in one headless module.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    keystore_module = {
      # With identity keys (ed25519): corpetty/logos-evm-keystore-module feat/ed25519-identity.
      url = "github:corpetty/logos-evm-keystore-module/1c819f220c9dd280a5f153296c57368efb866cc3";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    signer_manager_module = {
      url = "github:corpetty/logos-signer-manager-module/feat/ed25519-record";
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
