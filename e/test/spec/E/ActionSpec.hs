{-# Language OverloadedStrings #-}
{-# Language TypeApplications #-}

module E.ActionSpec (main, spec) where

import qualified Data.Text.IO as TIO
import System.Directory (doesFileExist)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)

import E

import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec =

  describe "Action" $ do

    let template = "password = " `Txt` ((PlainValue (ValName "password") (AlgName "dummy") mempty (PlainContent "qwerty123!")) `Val` Nil)

    it "performs ActEnc without existing metadata writing to file" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      let metafilepath = d </> ".file.e"
      TIO.writeFile filepath (encode template)
      let action = ActEnc dummy (InFP filepath) Nothing (OutFP filepath) (OutMetaFP metafilepath)
      doesFileExist metafilepath `shouldReturn` False
      runEitherT (runActResult (act action)) `shouldReturn` (Right ())
      doesFileExist metafilepath `shouldReturn` True

    it "performs ActEnc without existing metadata writing to output" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      let metafilepath = d </> ".file.e"
      TIO.writeFile filepath (encode template)
      let action = ActEnc dummy (InFP filepath) Nothing OutStd (OutMetaFP metafilepath)
      doesFileExist metafilepath `shouldReturn` False
      runEitherT (runActResult (act action)) `shouldReturn` (Right ())
      doesFileExist metafilepath `shouldReturn` True
      TIO.readFile filepath `shouldReturn` encode template

    it "performs ActEnc with existing metadata" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      TIO.writeFile filepath (encode template)
      let metafilepath = d </> ".file.e"
      TIO.writeFile metafilepath (encode @Metadata mempty)
      let action = ActEnc dummy (InFP filepath) (Just (InMetaFP metafilepath)) (OutFP filepath) (OutMetaFP metafilepath)
      runEitherT (runActResult (act action)) `shouldReturn` (Right ())
      doesFileExist metafilepath `shouldReturn` True

    it "throws InputMetadataFileNotFound when metadata file is absent" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      TIO.writeFile filepath (encode template)
      let metafilepath = d </> ".file.e"
      doesFileExist metafilepath `shouldReturn` False
      let action = ActEnc dummy (InFP filepath) (Just (InMetaFP metafilepath)) (OutFP filepath) (OutMetaFP metafilepath)
      runEitherT (runActResult (act action)) `shouldReturn` Left (InputMetadataFileNotFound (InMetaFP metafilepath))
      TIO.readFile filepath `shouldReturn` encode template

    it "throws MetadataParsingError when metadata is invalid" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      TIO.writeFile filepath (encode template)
      let metafilepath = d </> ".file.e"
      TIO.writeFile metafilepath "invalid metadata"
      let action = ActEnc dummy (InFP filepath) (Just (InMetaFP metafilepath)) (OutFP filepath) (OutMetaFP metafilepath)
      Left (MetadataParsingError _ ) <- runEitherT (runActResult (act action))
      doesFileExist metafilepath `shouldReturn` True
      TIO.readFile filepath `shouldReturn` encode template

    it "throws InputFileNotFound when input file is absent" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      doesFileExist filepath `shouldReturn` False
      let metafilepath = d </> ".file.e"
      let action = ActEnc dummy (InFP filepath) Nothing (OutFP filepath) (OutMetaFP metafilepath)
      runEitherT (runActResult (act action)) `shouldReturn` Left (InputFileNotFound (InFP filepath))

    it "throws EncryptionError when encryption algorithm isn't supported" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      let metafilepath = d </> ".file.e"
      TIO.writeFile filepath (encode template)
      let action = ActEnc mempty (InFP filepath) Nothing (OutFP filepath) (OutMetaFP metafilepath)
      runEitherT (runActResult (act action)) `shouldReturn` Left (EncryptionError (AlgNotFound (AlgName "dummy")))
      doesFileExist metafilepath `shouldReturn` False
      TIO.readFile filepath `shouldReturn` encode template

    it "performs ActDec writing to file" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      let metafilepath = d </> ".file.e"
      Right (templateEnc, meta) <- runEitherT (encryptTem dummy mempty template)
      TIO.writeFile filepath (encode templateEnc)
      TIO.writeFile metafilepath (encode meta)
      let action = ActDec dummy (InFP filepath) (InMetaFP metafilepath) (OutFP filepath)
      runEitherT (runActResult (act action)) `shouldReturn` (Right ())
      TIO.readFile filepath `shouldNotReturn` encode templateEnc
      TIO.readFile metafilepath `shouldReturn` encode meta

    it "performs ActDec writing to output" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      let metafilepath = d </> ".file.e"
      Right (templateEnc, meta) <- runEitherT (encryptTem dummy mempty template)
      TIO.writeFile filepath (encode templateEnc)
      TIO.writeFile metafilepath (encode meta)
      let action = ActDec dummy (InFP filepath) (InMetaFP metafilepath) OutStd
      runEitherT (runActResult (act action)) `shouldReturn` (Right ())
      TIO.readFile filepath `shouldReturn` encode templateEnc
      TIO.readFile metafilepath `shouldReturn` encode meta

    it "throws DecryptionError when template has PlainValue" $ withSystemTempDirectory "dir" $ \d -> do
      let filepath = d </> "file"
      let metafilepath = d </> ".file.e"
      TIO.writeFile filepath (encode template)
      TIO.writeFile metafilepath (encode @Metadata mempty)
      let action = ActDec dummy (InFP filepath) (InMetaFP metafilepath) (OutFP filepath)
      runEitherT (runActResult (act action)) `shouldReturn` (Left (DecryptionError (DecryptingPlain (ValName "password"))))
      TIO.readFile filepath `shouldReturn` encode template
