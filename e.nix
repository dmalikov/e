{ mkDerivation, base, base64-bytestring, bytestring, cipher-aes
, crypto-cipher-types, directory, DRBG, either, filepath, hspec
, optparse-applicative, process, random, RSA, stdenv, text
, transformers, unordered-containers
}:
mkDerivation {
  pname = "e";
  version = "0.0.0";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    base base64-bytestring bytestring cipher-aes crypto-cipher-types
    directory DRBG either filepath random RSA text transformers
    unordered-containers
  ];
  executableHaskellDepends = [
    base bytestring optparse-applicative text
  ];
  testHaskellDepends = [
    base base64-bytestring bytestring cipher-aes crypto-cipher-types
    directory DRBG filepath hspec process random RSA text
  ];
  description = "Text encrypting using RSA and AES-GCM";
  license = stdenv.lib.licenses.mit;
}
