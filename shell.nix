{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc7102" }: let
  inherit (nixpkgs) pkgs;
  ghc = pkgs.haskell.packages.${compiler}.ghcWithPackages( ps: with ps; [
    cabal2nix doctest hasktags hspec-discover standalone-haddock stylish-haskell
  ]);
  hdevtools = pkgs.haskell.packages.${compiler}.callPackage ./hdevtools.nix { };
  cabal-install = pkgs.haskell.packages.${compiler}.cabal-install;
  pkg = (import ./default.nix { inherit nixpkgs compiler; });
in
  pkgs.stdenv.mkDerivation rec {
    name = pkg.pname;
    buildInputs = [ ghc cabal-install hdevtools ] ++ pkg.env.buildInputs;
    shellHook = ''
      ${pkg.env.shellHook}
      export IN_WHICH_NIX_SHELL=${name}
      cabal configure --enable-tests --package-db=$NIX_GHC_LIBDIR/package.conf.d
    '';
  }
