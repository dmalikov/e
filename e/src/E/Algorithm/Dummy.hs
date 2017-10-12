{-# LANGUAGE OverloadedStrings #-}

-- | Example of simplest identity encryption.
module E.Algorithm.Dummy (dummy) where

import E.Encrypt
import E.Template

-- | Cipher/deciphering without any change.
dummy :: Algs
dummy = algorithm (AlgName "dummy") (Cipher dummyCipher) (Decipher dummyDecipher)
  where
    dummyCipher _ (PlainContent c) = pure $ EncContent c
    dummyDecipher _ (EncContent c) = pure $ PlainContent c
