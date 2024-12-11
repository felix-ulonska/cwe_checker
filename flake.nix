{
  description = "Nix flake with Ghidra as a dependency";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages."x86_64-linux";
      # == Building Ghidra == 
      ghidra-cwe-checker-plugin = pkgs.ghidra.buildGhidraScripts {
        pname = "cwe_checker";
        name = "cwe_checker";
        src = ./ghidra_plugin;
      };
      cwe-ghidra = pkgs.ghidra.withExtensions (p: with p; [ ghidra-cwe-checker-plugin ]);
      # Path to java ghidra plugin
      ghidra_pcode_extract = pkgs.runCommand 
        "pcode_extractor" { src = ./src/ghidra/p_code_extractor; }
        ''
        mkdir -p $out/p_code_extractor
        cp -rf $src/* $out/p_code_extractor
        '';
      # Build ghidra package with analyzeHeadless in support/ where it is the default
      # cwe_checker expectes it in support/
      cwe-ghidra-path-fix = pkgs.stdenv.mkDerivation {
        name = "analyzeHeadless";
        pname = "analyzeHeadless";
        buildInputs = [ cwe-ghidra ];
        src = cwe-ghidra;
        buildPhase = ''
        mkdir -p $out
        cp -rf ${cwe-ghidra} $out
        # cwe checker expects 
        mkdir -p $out/support
        cp ${cwe-ghidra}/bin/ghidra-analyzeHeadless $out/support/analyzeHeadless
        '';
      };
      # == Building cwe_checker ==
      cwe-checker-bins = pkgs.rustPlatform.buildRustPackage {
        pname = "cwe_checker";
        name = "cwe_checker";
        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
        };
      };
      # Build ghidra.json
      cwe-ghidra-json = pkgs.writeTextFile {
        name = "GhidraConfigFile";
        text = builtins.toJSON { ghidra_path = ''${cwe-ghidra-path-fix}''; };
      };
      # creates config dir for cwe_checker
      cwe-checker-config = pkgs.runCommand "configs" { src = ./src; } 
      ''
      mkdir -p $out
      cp $src/config.json $out
      cp $src/lkm_config.json $out
      ln -s ${cwe-ghidra-json} $out/ghidra.json
      '';
      # target bin for nix run .#
      cwe-checker = pkgs.writeScriptBin "cwe-checker" ''
      #!/bin/sh
      CWE_CHECKER_CONFIGS_PATH=${cwe-checker-config} \
      CWE_CHECKER_GHIDRA_PLUGINS_PATH=${ghidra_pcode_extract} \
      ${cwe-checker-bins}/bin/cwe_checker $@;
      '';
    in
    {
      devShell.x86_64-linux = pkgs.mkShell {
        buildInputs = with pkgs; [
          rustc
          cargo
          cwe-ghidra-path-fix
        ];
        shellHook = ''
        export CWE_CHECKER_CONFIGS_PATH=${cwe-checker-config} \
        export CWE_CHECKER_GHIDRA_PLUGINS_PATH=${ghidra_pcode_extract} \
        '';
      };
      packages.x86_64-linux.default = cwe-checker;
    };
}

