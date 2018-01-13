{-# LANGUAGE LambdaCase #-}
module Run where

import Data.Monoid
import System.Directory (doesFileExist)
import System.Exit (die, exitSuccess)

import Args
import E
import E.Algorithm.AesGcm
import E.Algorithm.Gpgme

algs :: Algs
algs = dummy <> aesgcm <> gpgme

toMetadata :: FilePath -> FilePath
toMetadata f = "." ++ f ++ ".e"

runAction :: Action -> IO ()
runAction action = do
  actionResult <- runExceptT . runActResult $ act action
  case actionResult of
    Left actError -> die (describeE actError)
    Right _       -> exitSuccess

run :: ExeAction -> IO ()
run = \case
  Enc ifp dump -> do
    metadataExists <- doesFileExist (toMetadata ifp)
    let meta = if metadataExists then Just (InMetaFP (toMetadata ifp)) else Nothing
    let out = if dump then OutStd else OutFP ifp
    runAction (ActEnc algs (InFP ifp) meta out (OutMetaFP (toMetadata ifp)))
  Dec ifp dump -> do
    let out = if dump then OutStd else OutFP ifp
    runAction (ActDec algs (InFP ifp) (InMetaFP (toMetadata ifp)) out)
  Help -> putStrLn $ unlines
    [ "e"
    , "e enc <input file> [--dump]"
    , "    encrypt file"
    , "e dec <input file> [--dump]"
    , "    decrypt file"
    ]
