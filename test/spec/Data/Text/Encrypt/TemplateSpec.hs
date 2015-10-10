{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns      #-}
module Data.Text.Encrypt.TemplateSpec
  ( main, spec
  ) where

import           Control.E.Keys
import           Control.Monad              (when)
import qualified Data.Text.Encrypt.Template as TET
import qualified Data.Text.Lazy             as TL
import           System.Directory           (doesFileExist, removeFile)
import           System.FilePath            ((</>))
import           System.Random
import           Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "encrypt templating" $ do
    context "encrypt" $ do
      it "doesn't modify a plain text" $
        TET.encrypt "plain text" `shouldReturn` Right "plain text"
      it "fails when closing parens are missing" $
        TET.encrypt "hey {{where|is it?" `shouldReturn` Left (TET.EncryptSyntaxError TET.MissingClosingParens)
      it "fails when plain text section is missing" $
        TET.encrypt "hey {{where}}" `shouldReturn` Left TET.MissingPlainText
      it "fails when publicKey is absent" $ do
        TET.encrypt "ok {{absentKey|is absent}}" `shouldReturn` Left TET.PublicKeyNotFound
    context "decrypt" $ do
      it "doesn't modify a plain text" $
        TET.decrypt "plain text" `shouldReturn` Right "plain text"
      it "fails when format is invalid" $
        TET.decrypt "invalid {{format}}" `shouldReturn` Left (TET.DecryptSyntaxError TET.InvalidFormat)
      it "fails when privateKey is absent" $
        TET.decrypt "this {{key|is|absent}} sorry" `shouldReturn` Left TET.PrivateKeyNotFound
    context "encrypt / decrypt" $ do
      it "encrypts and decrypts text with a single hole" $ do
        keyId <- randomStr 10
        putStrLn ("Generating key <" ++ keyId ++ ">")
        generate (Just keyId)
        original <- randomStr 30
        let value = "{{" ++ keyId ++ "|" ++ original ++ "}}"
        putStrLn ("encrypt templating <" ++ value ++ ">")
        TET.encrypt (TL.pack value) >>= \case
          Left e          -> error ("template enryption failed: " ++ show e)
          Right encrypted -> do
            putStrLn ("decrypt templating <" ++ (TL.unpack encrypted) ++ ">")
            TET.decrypt encrypted >>= \case
              Left e                         -> error ("template decryption failed: " ++ show e)
              Right (TL.unpack -> decrypted) -> do
                putStrLn ("decrypted <" ++ decrypted ++ ">")
                decrypted `shouldBe` original
        removeKey keyId
      it "encrypts and decrypts text with number of holes" $ do
        keyId <- randomStr 10
        putStrLn ("Generating key <" ++ keyId ++ ">")
        generate (Just keyId)
        original1 <- randomStr 30
        original2 <- randomStr 30
        let value = "some text \n and more {{" ++ keyId ++ "|" ++ original1 ++ "}} more {{" ++
                    keyId ++ "|" ++ original2 ++ "}} well that's enough"
        putStrLn ("encrypt templating <" ++ value ++ ">")
        TET.encrypt (TL.pack value) >>= \case
          Left e          -> error ("template enryption failed: " ++ show e)
          Right encrypted -> do
            putStrLn ("decrypt templating <" ++ (TL.unpack encrypted) ++ ">")
            TET.decrypt encrypted >>= \case
              Left e                         -> error ("template decryption failed: " ++ show e)
              Right (TL.unpack -> decrypted) -> do
                putStrLn ("decrypted <" ++ decrypted ++ ">")
                decrypted `shouldBe` "some text \n and more " ++ original1 ++ " more " ++ original2 ++ " well that's enough"
        removeKey keyId


removeKey :: String -> IO ()
removeKey keyId = do
  privateKeyFile <- (</> keyId ++ ".private") <$> getStorePath
  publicKeyFile  <- (</> keyId ++ ".public")  <$> getStorePath
  whenM (doesFileExist privateKeyFile) $
    removeFile privateKeyFile
  whenM (doesFileExist publicKeyFile) $
    removeFile publicKeyFile
 where
  whenM :: IO Bool -> IO () -> IO ()
  whenM monadBool action = do
    bool' <- monadBool
    when bool' action

randomStr :: Int -> IO String
randomStr n = take n . randomRs ('a','z') <$> newStdGen
