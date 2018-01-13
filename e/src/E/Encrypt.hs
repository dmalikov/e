{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Encryption / decryption primitives over 'Tem' and 'Metadata'.

module E.Encrypt
  (
  -- * Basic encryption primitives
    Cipher(..)
  , Decipher(..)
  -- * Container of multiple encryption algorithms
  , Algs(..)
  , algorithm
  -- * Operations on 'Tem'
  , encryptTem
  , decryptTem
  -- * Exceptions
  , EError(..)
  ) where

import Control.Monad.Trans.Except
import Data.Either.MoreCombinators
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as Map
import Data.Semigroup
import Data.Text (Text)

import E.Metadata
import E.Template

-- | Algorithms container. Mapping from 'AlgName' to corresponde 'Cipher' and 'Decipher' routine.
newtype Algs = Algs
  { unAlgs :: HashMap AlgName (Cipher, Decipher) }

-- | Semigroup over inner map.
instance Semigroup Algs where
  Algs xs <> Algs ys = Algs (xs <> ys)
  {-# INLINE (<>) #-}

-- | Monoid over inner map.
instance Monoid Algs where
  mappend = (<>)
  {-# INLINE mappend #-}
  mempty = Algs mempty
  {-# INLINE mempty #-}

-- | Cipher routine.
newtype Cipher = Cipher
  { runCipher :: Args -> PlainContent -> ExceptT Text IO EncContent }

-- | Decipher routine.
newtype Decipher = Decipher
  { runDecipher :: Args -> EncContent -> ExceptT Text IO PlainContent }

-- | Build 'Algs' with a single algorithm.
algorithm :: AlgName -> Cipher -> Decipher -> Algs
algorithm n c d = Algs (Map.singleton n (c, d))

-- | Exception during encrypting/decrypting the 'Tem'.
data EError
  = AlgNotFound AlgName -- ^ 'EAlg' is not supported.
  | ValNotFound ValName -- ^ 'ValName' is not defined.
  | DecryptingPlain ValName -- ^ 'Tem' contains 'PlainValue' values that cannot be decrypted.
  | MetadataError MetadataError -- ^ 'Metadata' operation failed.
  | CipherError AlgName Text -- ^ Error during ciphering using 'AlgName' algorithm.
  | DecipherError AlgName Text -- ^ Error during deciphering using 'AlgName' algorithm.
    deriving (Eq,Show)

-- | Encrypt plain value with algorithms container.
cipher :: Algs -> PlainValue -> ExceptT EError IO EncValue
cipher algs (PlainValue _ alg args content) =
  case Map.lookup alg (unAlgs algs) of
    Just (Cipher enc, _) -> bimapExceptT (CipherError alg) (EncValue alg args) (enc args content)
    Nothing -> left (AlgNotFound alg)

-- | Decrypt ciphered value with algorithms container.
decipher :: ValName -> Algs -> EncValue -> ExceptT EError IO PlainValue
decipher name algs (EncValue alg args content) =
  case Map.lookup alg (unAlgs algs) of
    Just (_, Decipher dec) -> bimapExceptT (DecipherError alg) (PlainValue name alg args) (dec args content)
    Nothing -> left (AlgNotFound alg)

-- | Encrypt template with algorithms container and metadata.
--
-- /Note/: ciphered values will be left intact.
encryptTem :: Algs -> Metadata -> Tem -> ExceptT EError IO (Tem, Metadata)
encryptTem e = et
 where
  et meta Nil = right (Nil, meta)
  et meta (Txt text template) = do
    (template', meta') <- et meta template
    right (Txt text template', meta')
  et meta (Val evp@(PlainValue name _ _ _) template) = do
    ciphered <- cipher e evp
    (template', meta') <- et meta template
    meta'' <- hoistEither (mapLeft MetadataError (addCiphered name ciphered meta'))
    right (Ref (ValRef name) template', meta'')
  et meta (Ref eValueName template) = do
    (template', meta') <- et meta template
    pure (Ref eValueName template', meta')

-- | Decrypt template with algorithms container and metadata.
--
-- /Note/: if plain value occurred, 'DecryptingPlain' will be returned.
decryptTem :: Algs -> Metadata -> Tem -> ExceptT EError IO Tem
decryptTem e = dt
 where
  dt _ Nil = right Nil
  dt meta (Txt text template) = right . Txt text =<< dt meta template
  dt _ (Val (PlainValue name _ _ _) _) = left (DecryptingPlain name)
  dt meta (Ref (ValRef name) template) = do
    ciphered <- hoistEither (note (ValNotFound name) (getCiphered name meta))
    PlainValue _ _ _ (PlainContent content) <- decipher name e ciphered
    template' <- dt meta template
    right (Txt content template')
