{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeSynonymInstances       #-}

-- | Encrypted values store.

module E.Metadata
  ( Metadata(..)
  , MetadataError(..)
  , E.Metadata.singleton
  , addCiphered
  , getCiphered
  ) where

import Control.Lens
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as Aeson
import Data.Aeson.Encode.Pretty
import qualified Data.ByteString.Lazy as BSL
import Data.Either.MoreCombinators
import Data.Hashable
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as Map
import Data.Semigroup
import Data.Text.Encoding
import GHC.Generics
import qualified Data.Text.Lazy as TL
import Data.Text.Lazy.Builder

import E.Template

-- | Metadata-specific exceptions.
data MetadataError
  = MetadataInconsistentValues ValName -- ^ Updating existing variable with different value
    deriving (Eq,Show)

-- | Store of encrypted value indexed by 'ValName'.
newtype Metadata = Metadata { unMetadata :: HashMap ValName EncValue }
  deriving (Show,Eq,Generic,FromJSON,ToJSON)

-- | Semigroup over inner map.
instance Semigroup Metadata where
  Metadata x <> Metadata y = Metadata (x <> y)

-- | Monoid over inner map.
instance Monoid Metadata where
  mappend = (<>)
  mempty = Metadata mempty

-- | Metadata with single value.
singleton :: ValName -> EncValue -> Metadata
singleton v c = Metadata (Map.singleton v c)

-- | Insert to 'HashMap' if such key is absent or exist with given value, otherwise 'Nothing'.
insert' :: (Eq k, Hashable k, Eq v) => k -> v -> HashMap k v -> Maybe (HashMap k v)
insert' k v m = either id Just (at k aux m)
 where
  aux Nothing = Right (Just v)
  aux (Just v') | v' == v = Left (Just m)
                | otherwise = Left Nothing

-- | Add 'EncValue' to 'Metadata'.
addCiphered :: ValName -> EncValue -> Metadata -> Either MetadataError Metadata
addCiphered name evc (Metadata m) = Metadata <$>
  note (MetadataInconsistentValues name) (insert' name evc m)

-- | Get 'EncValue' from 'Metadata'.
getCiphered :: ValName -> Metadata -> Maybe EncValue
getCiphered v (Metadata m) = Map.lookup v m

-- | Serialize / deserialize via 'Aeson.encode' / 'Aeson.decode'.
instance Serialize Metadata where
  encode = TL.toStrict . toLazyText . encodePrettyToTextBuilder' (defConfig { confCompare = keyOrder ["name", "alg", "value", "args"] })
  decode = Aeson.decode . BSL.fromStrict . encodeUtf8
