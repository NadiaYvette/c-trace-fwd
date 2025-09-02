{
  description = "C trace library";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs.url = "nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let

      # to work with older version of flakes
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      # Generate a user-friendly version number.
      version = builtins.substring 0 8 lastModifiedDate;

      # System types to support.
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; overlays = [ self.overlay ]; });

    in

    {

      # A Nixpkgs overlay.
      overlay = final: prev: {

        c-trace-fwd = with nixpkgs; with final; stdenv.mkDerivation rec {
          pname = "c-trace-fwd";
          inherit version;

          src = ./.;

          # nativeBuildInputs = [ autoreconfHook ];
          # nativeBuildInputs = [ ];
          # phases = [ buildPhase installPhase ];
          buildInputs = [clang coreutils gcc glib glibc gnumake libcbor pkgconf];
          buildTarget = ''
            all
          '';
          buildPhase = ''
            make -f Makefile all
          '';
          installPhase = ''
            mkdir -p $out/bin
            mkdir -p $out/lib
            cp obj/bin/c_trace_fwd $out/bin
            cp obj/lib/libc_trace_fwd.so $out/lib
          '';
        };

      };

      # Provide some binary packages for selected system types.
      packages = forAllSystems (system:
        {
          inherit (nixpkgsFor.${system}) c-trace-fwd;
        });

      # The default package for 'nix build'. This makes sense if the
      # flake provides only one package or there is a clear "main"
      # package.
      defaultPackage = forAllSystems (system: self.packages.${system}.c-trace-fwd);

      # A NixOS module, if applicable (e.g. if the package provides a system service).
      nixosModules.c-trace-fwd =
        { pkgs, ... }:
        {
          nixpkgs.overlays = [ self.overlay ];

          environment.systemPackages = [ pkgs.c-trace-fwd ];

          #systemd.services = { ... };
        };

      # Tests run by 'nix flake check' and by Hydra.
      checks = forAllSystems
        (system:
          with nixpkgsFor.${system};

          {
            inherit (self.packages.${system}) c-trace-fwd;

            # Additional tests, if applicable.
            test = stdenv.mkDerivation {
              pname = "c-trace-fwd";
              inherit version;

              buildInputs = [ c-trace-fwd ];

              dontUnpack = true;

              buildPhase = ''
                echo 'running some integration tests'
                [[ $(c-trace-fwd) = 'Hello Nixers!' ]]
              '';

              installPhase = "mkdir -p $out";
            };
          }

          // lib.optionalAttrs stdenv.isLinux {
            # A VM test of the NixOS module.
            vmTest =
              with import (nixpkgs + "/nixos/lib/testing-python.nix") {
                inherit system;
              };

              makeTest {
                nodes = {
                  client = { ... }: {
                    imports = [ self.nixosModules.c-trace-fwd ];
                  };
                };

                testScript =
                  ''
                    start_all()
                    client.wait_for_unit("multi-user.target")
                    client.succeed("c-trace-fwd")
                  '';
              };
          }
        );

    };
}
