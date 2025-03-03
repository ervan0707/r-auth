{
  description = "R-Auth - TOTP Authenticator CLI";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Read Cargo.toml
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        pname = cargoToml.package.name;
        version = cargoToml.package.version;

        # Cross-compilation settings
        crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;

        # Platform-specific dependencies
        platformDeps = with pkgs;
          let
            isDarwin = builtins.match ".*darwin" system != null;
            isLinux = builtins.match ".*linux" system != null;
          in
            if isLinux then [
              dbus
              libsecret
            ] else if isDarwin then [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.CoreFoundation
            ] else [];

        # System-specific library path
        libraryPath = with pkgs.lib;
          if (system == "x86_64-linux" || system == "aarch64-linux")
          then makeLibraryPath [ pkgs.dbus pkgs.libsecret ]
          else "";

        # Build for the current platform
        nativePkg = pkgs.rustPlatform.buildRustPackage {
          inherit pname version;
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          buildInputs = platformDeps;

          nativeBuildInputs = with pkgs; [
            pkg-config
            openssl
          ];

          LD_LIBRARY_PATH = libraryPath;
        };

        # Cross-compilation package for aarch64-linux
        crossPkg = crossPkgs.rustPlatform.buildRustPackage {
          inherit pname version;
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          buildInputs = with crossPkgs; [
            dbus
            libsecret
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
            openssl
          ];

          CARGO_BUILD_TARGET = "aarch64-unknown-linux-gnu";
        };

      in
      {
        packages = {
          default = nativePkg;
          ${pname} = nativePkg;
          "${pname}-aarch64-linux" = crossPkg;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rust-bin.stable.latest.default
            pkg-config
            openssl
          ] ++ platformDeps;

          shellHook =
            if (system == "x86_64-linux" || system == "aarch64-linux")
            then ''
              export LD_LIBRARY_PATH=${libraryPath}:$LD_LIBRARY_PATH
            ''
            else "";
        };
      }
    );
}
