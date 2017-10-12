{-# Language OverloadedStrings #-}
{-# Language TypeApplications #-}
module E.MetadataSpec (main, spec) where

import Test.Hspec
import Test.Hspec.QuickCheck
import qualified Data.Aeson as A
import Data.Aeson.Types
import Data.Binary.Builder (toLazyByteString)

import qualified Data.HashMap.Strict as Map

import E.Metadata
import E.Template hiding (parseMaybe)
import Arbitrary ()

main :: IO ()
main = hspec spec

spec :: Spec
spec =
  describe "Metadata" $ do

    it "can be mappended" $ do
      let v1 = EncValue (AlgName "alg1") mempty (EncContent "!")
          v2 = EncValue (AlgName "alg2") mempty (EncContent "!")
      unMetadata (singleton (ValName "a") v1 `mappend` singleton (ValName "b") v2) `shouldBe`
        Map.fromList [ (ValName "a", v1), (ValName "b", v2) ]

    it "has valid Show instance" $ do
      showList @Metadata mempty "" `shouldBe` "[]"
      showList [MetadataInconsistentValues (ValName "a")] "" `shouldBe`
        "[MetadataInconsistentValues (ValName {unValName = \"a\"})]"

    it "has valid Eq instance" $ do
      Metadata mempty `shouldNotBe` singleton (ValName "a") (EncValue (AlgName "a") mempty (EncContent "!"))
      MetadataInconsistentValues (ValName "a") `shouldNotBe`
        MetadataInconsistentValues (ValName "b")

    it "has valid ToJSON/FromJSON instances" $ do
      let meta = singleton (ValName "var") (EncValue (AlgName "alg") mempty (EncContent "content"))
      parseMaybe parseJSONList (toJSONList [meta]) `shouldBe` Just [meta]
      toLazyByteString (fromEncoding (toEncodingList [meta])) `shouldBe`
        "[{\"var\":{\"alg\":\"alg\",\"value\":\"content\"}}]"

    context "Encoding" $
      prop "decode . encode == id" $
        \t -> decode (encode t) == Just (t :: Metadata)

    context "JSON encoding" $
      prop "ToJSON . encode == id" $
        \t -> A.decode (A.encode t) == Just (t :: Metadata)
