{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ...}@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs {inherit system;};
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "c-trace-fwd";
          version = "0.1.0";
          src = ./.;
          buildInputs = with pkgs; [ gcc ];
          buildPhase = "make";
          installPhase = "install -D c_trace_fwd $out/bin/c_trace_fwd";
        };
        devShell = pkgs.mkShell { buildInputs = []; };
      }
    )
  ;

}
