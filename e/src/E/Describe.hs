{-# LANGUAGE OverloadedStrings #-}
-- | Meaningful error messages.

module E.Describe where

import qualified Data.Text as Text

import E.Action
import E.Encrypt
import E.Metadata
import E.Template

-- | Descriptive error with meaningful message.
class Descriptive a where
  describeE :: a -> String

instance Descriptive ActError where
  describeE (InputFileNotFound (InFP filepath)) = "No such input file " ++ filepath
  describeE (InputMetadataFileNotFound (InMetaFP filepath)) = "No such input metadata file " ++ filepath
  describeE (MetadataParsingError errInfo) = "Error during metadata parsing: " ++ errInfo
  describeE (EncryptionError eerror) = "Error during encryption: " ++ describeE eerror
  describeE (DecryptionError eerror) = "Error during decryption: " ++ describeE eerror

instance Descriptive EError where
  describeE (AlgNotFound (AlgName alg)) = Text.unpack $ Text.concat [ "Encrypt/decrypt algorithm \"",  alg, "\" not found" ]
  describeE (ValNotFound (ValName value)) = Text.unpack $ Text.concat [ "Value \"", value, "\" not found" ]
  describeE (DecryptingPlain (ValName value)) = Text.unpack $ "Cannot decrypt plain value \"" `Text.append` value `Text.append` "\""
  describeE (MetadataError metadataError) = "Failed to process metadata: " ++ describeE metadataError
  describeE (CipherError (AlgName alg) text) = Text.unpack $ Text.concat [ "\"", text, "\": cannot cipher with \"", alg, "\" algorithm" ]
  describeE (DecipherError (AlgName alg) text) = Text.unpack $ Text.concat [ "\"", text, "\": cannot decipher with \"", alg, "\" algorithm" ]

instance Descriptive MetadataError where
  describeE (MetadataInconsistentValues (ValName name)) = Text.unpack $ Text.concat
      [ "Cannot add value \""
      , name
      , "\" to metadata since it's already there with a different value"
      ]
