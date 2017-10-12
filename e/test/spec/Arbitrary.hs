{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Arbitrary
  ( ValName(..)
  , AlgName(..)
  , Args(..)
  , ArgName(..)
  , ArgValue(..)
  , ValRef(..)
  , PlainValue(..)
  , EncValue(..)
  , PlainContent(..)
  , EncContent(..)
  , Tem(..)
  , Metadata(..)
  ) where

import Control.Monad (liftM2, liftM3, liftM4)
import qualified Data.HashMap.Strict as Map
import Data.Text (Text)
import qualified Data.Text as Text
import Test.QuickCheck hiding (Args)
import Test.QuickCheck.Instances ()

import E.Metadata
import E.Template

nonEmptyText :: Gen Text
nonEmptyText = Text.pack <$> listOf1 (elements (['a' .. 'z'] ++ ['A' .. 'Z'] ++ ['0' .. '9']))

instance Arbitrary ValName where
  arbitrary = ValName <$> nonEmptyText

instance Arbitrary AlgName where
  arbitrary = AlgName <$> nonEmptyText

instance Arbitrary Args where
  arbitrary = Args . Map.fromList <$> listOf1 arbitrary

instance Arbitrary ArgName where
  arbitrary = ArgName <$> nonEmptyText

instance Arbitrary ArgValue where
  arbitrary = ArgValue <$> nonEmptyText

instance Arbitrary ValRef where
  arbitrary = ValRef <$> arbitrary

instance Arbitrary PlainValue where
  arbitrary = liftM4 PlainValue arbitrary arbitrary arbitrary arbitrary

instance Arbitrary EncValue where
  arbitrary = liftM3 EncValue arbitrary arbitrary arbitrary

instance Arbitrary PlainContent where
  arbitrary = PlainContent <$> nonEmptyText

instance Arbitrary EncContent where
  arbitrary = EncContent <$> nonEmptyText

instance Arbitrary Tem where
  arbitrary = eTemplate
   where
    eTemplate = normalize <$> sized eTemplate'
    eTemplate' 0 = pure Nil
    eTemplate' _ = oneof [ pure Nil
                         , liftM2 Txt nonEmptyText arbitrary
                         , liftM2 Val arbitrary arbitrary
                         , liftM2 Ref arbitrary arbitrary
                         ]

instance Arbitrary Metadata where
  arbitrary = Metadata . Map.fromList <$> listOf1 arbitrary
