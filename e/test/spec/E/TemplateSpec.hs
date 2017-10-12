{-# Language OverloadedStrings #-}
{-# Language TypeApplications #-}
module E.TemplateSpec (main, spec) where

import Data.Monoid
import qualified Data.Text as Text
import qualified Data.Aeson as A

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck hiding (Args)

import E.Template
import Arbitrary ()

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "ArgName, ArgValue" $
    context "parseArgNV" $ do
      it "can't handle empty pair" $
        parseMaybe parseArgNV "" `shouldBe` Nothing
      context "handle single pair" $ do
        it "when variable contains single letter" $
          parseMaybe parseArgNV "k = v" `shouldBe` Just (ArgName "k", ArgValue "v")
        it "when variable contains multiple letters" $
          parseMaybe parseArgNV "k = value" `shouldBe` Just (ArgName "k", ArgValue "value")
        it "when variable contains digits" $
          parseMaybe parseArgNV "k = 11" `shouldBe` Just (ArgName "k", ArgValue "11")
        it "when variable name and value contain digits and letters" $
          parseMaybe parseArgNV "what1ever = el2se" `shouldBe` Just (ArgName "what1ever", ArgValue "el2se")
      it "drops trailing whitespaces" $
        parseMaybe parseArgNV "   key   =    value  " `shouldBe` parseMaybe parseArgNV "key = value"

  describe "Args" $
    context "parseArgs" $ do
      it "handles empty args" $
        decode @Args "" `shouldBe` Just mempty
      it "handles single arg" $
        decode "k = v" `shouldBe` Just (arg (ArgName "k") (ArgValue "v"))
      it "handles multiple args" $
        decode "k1 = v1, k2 = v2" `shouldBe` Just (arg (ArgName "k1") (ArgValue "v1") <> arg (ArgName "k2") (ArgValue "v2"))
      it "drops trailing whitespaces" $
        decode @Args "     k1    =   v1,     k2   =   v2   " `shouldBe` decode "k1 = v1, k2 = v2"

  describe "PlainValue" $
    context "parsePlainValue" $ do
      it "handles value without args" $
        parseMaybe parsePlainValue "{{P|password|gpgme||qwerty}}" `shouldBe`
          Just (PlainValue (ValName "password") (AlgName "gpgme") mempty (PlainContent "qwerty"))
      it "handles value with args" $
        parseMaybe parsePlainValue "{{P|password|gpgme|keyId = mykey|qwerty}}" `shouldBe`
          Just (PlainValue (ValName "password") (AlgName "gpgme") (arg (ArgName "keyId") (ArgValue "mykey")) (PlainContent "qwerty"))
      it "handles value surrounded by whitespaces" $
        parseMaybe parsePlainValue "{{P|password|gpgme||   qwerty  }}" `shouldBe`
          Just (PlainValue (ValName "password") (AlgName "gpgme") mempty (PlainContent "   qwerty  "))
      it "handles multiline value" $
        parseMaybe parsePlainValue "{{P|password|gpgme||\nline\nline}}" `shouldBe`
          Just (PlainValue (ValName "password") (AlgName "gpgme") mempty (PlainContent "\nline\nline"))
      it "handles unclosed {{" $ do
        parseMaybe parsePlainValue "{{P|whatever|a|a=1" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|whatever|a|a=" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|whatever|a|a" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|whatever|a|" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|whatever|a" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|whatever|" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|whatever" `shouldBe` Nothing
        parseMaybe parsePlainValue "{{P|" `shouldBe` Nothing

  describe "ValRef" $
    context "parseValRef" $ do
      it "handles regular value" $
        parseMaybe parseValRef "{{E|password}}" `shouldBe` Just (ValRef (ValName "password"))
      it "drops value with trailing whitespaces" $
        parseMaybe parseValRef "{{E|  password  }}" `shouldBe` parseMaybe parseValRef "{{E|password}}"
      it "handles unclosed {{" $
        parseMaybe parseValRef "{{E|whatever" `shouldBe` Nothing

  describe "Template" $ do
    context "normalize" $ do
      it "don't change empty Template" $
        normalize Nil `shouldBe` Nil
      prop "don't change Template without neighboring Txt`s" $
        \t -> hasNoNeighTexts t ==> normalize t === t
      prop "idempotent" $
        \t -> normalize (normalize t) === normalize t
      it "squashes neighboring Txt`s" $
        normalize (txt "a" <> txt "b" <> txt "c") `shouldBe` txt "abc"
    context "parseTem" $ do
      it "handles empty template" $
        decode "" `shouldBe` Just Nil
      it "handles text-only template" $
        decode "Just a text\n!" `shouldBe` Just (txt "Just a text\n!")
      it "handles full template" $
        decode "user = 'username'\npassword = '{{P|password|gpg|keyId = mykey|pii}}'" `shouldBe`
          Just (txt "user = 'username'\npassword = '" <>
                val (PlainValue (ValName "password") (AlgName "gpg") (arg (ArgName "keyId") (ArgValue "mykey")) (PlainContent "pii")) <>
                txt "'")
      it "handles {{{ correctly" $
        decode "{{{E|password}}}" `shouldBe`
          Just (txt "{" <>
                ref (ValRef (ValName "password")) <>
                txt "}")
      it "handles unclosed {{" $ do
        decode "{{P|whatever" `shouldBe` Just (txt "{{P|whatever")
        decode "{{E|whatever" `shouldBe` Just (txt "{{E|whatever")
        decode "{{" `shouldBe` Just (txt "{{")

    context "Encoding" $ do
      prop "decode . encode == id" $ \t ->
        decode @Tem (encode t) == Just t

    context "Tem" $ do
      it "has valid Eq instance" $
        Nil `shouldNotBe` mempty `mappend` ref (ValRef (ValName "val")) <> Nil
      it "has valid Show instance" $
        showList [Nil] "" `shouldBe` "[Nil]"

    context "Tem internals" $ do

      it "has valid Eq instance" $ do
        ArgName "a" `shouldNotBe` ArgName "b"
        ArgValue "a" `shouldNotBe` ArgValue "b"
        ValName "a" `shouldNotBe` ValName "b"
        AlgName "a" `shouldNotBe` AlgName "b"
        arg (ArgName "a") (ArgValue "b") `shouldNotBe` arg (ArgName "c") (ArgValue "d")
        ValRef (ValName "a") `shouldNotBe` ValRef (ValName "b")
        unValRef (ValRef (ValName "a")) `shouldBe` (ValName "a")
        Text.pack "" `shouldBe` ""
        PlainContent "a" `shouldNotBe` PlainContent "b"
        EncContent "a" `shouldNotBe` EncContent "b"
        PlainValue (ValName "a") (AlgName "b") mempty (PlainContent "c") `shouldNotBe`
          PlainValue (ValName "d") (AlgName "e") mempty (PlainContent "f")
        EncValue (AlgName "a") mempty (EncContent "b") `shouldNotBe`
          EncValue (AlgName "c") mempty (EncContent "d")

      it "has valid Show instance" $ do
        showList [ArgName "a"] "" `shouldBe` "[ArgName {unArgName = \"a\"}]"
        showList [ArgValue "a"] "" `shouldBe` "[ArgValue {unArgValue = \"a\"}]"
        showList [ValName "a"] "" `shouldBe` "[ValName {unValName = \"a\"}]"
        showList [AlgName "a"] "" `shouldBe` "[AlgName {unAlgName = \"a\"}]"
        showList [arg (ArgName "a") (ArgValue "b")] "" `shouldBe`
          "[Args {unArgs = fromList [(ArgName {unArgName = \"a\"},ArgValue {unArgValue = \"b\"})]}]"
        showList [ValRef (ValName "a")] "" `shouldBe` "[ValRef {unValRef = ValName {unValName = \"a\"}}]"
        showList [PlainContent "a"] "" `shouldBe` "[PlainContent {unPlainContent = \"a\"}]"
        showList [EncContent "a"] "" `shouldBe` "[EncContent {unEncContent = \"a\"}]"
        showList [PlainValue (ValName "a") (AlgName "b") mempty (PlainContent "c")] "" `shouldBe`
          "[PlainValue (ValName {unValName = \"a\"}) (AlgName {unAlgName = \"b\"}) (Args {unArgs = fromList []}) (PlainContent {unPlainContent = \"c\"})]"
        showList [EncValue (AlgName "a") mempty (EncContent "b")] "" `shouldBe`
          "[EncValue (AlgName {unAlgName = \"a\"}) (Args {unArgs = fromList []}) (EncContent {unEncContent = \"b\"})]"

      it "has valid *JSON instances" $ do
        A.fromJSON @EncValue (A.toJSONList [EncValue (AlgName "a") mempty (EncContent "b")]) `shouldBe`
          A.Error "expected EncValue, encountered Array"

      it "has valid Ord instances" $ do
        ValName "a" `min` ValName "b" `shouldBe` ValName "a"
        AlgName "a" `min` AlgName "b" `shouldBe` AlgName "a"


hasNoNeighTexts :: Tem -> Bool
hasNoNeighTexts Nil               = True
hasNoNeighTexts (Txt _ (Txt _ _)) = False
hasNoNeighTexts (Val _ rest)      = hasNoNeighTexts rest
hasNoNeighTexts (Ref _ rest)      = hasNoNeighTexts rest
hasNoNeighTexts (Txt _ rest)      = hasNoNeighTexts rest
