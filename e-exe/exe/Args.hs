{-# LANGUAGE LambdaCase #-}

module Args where

data ExeAction = Enc String Bool | Dec String Bool | Help

parseArgs :: [String] -> ExeAction
parseArgs = \case
  ["enc", input, "--dump"] -> Enc input True
  ["enc", input] -> Enc input False
  ["dec", input, "--dump"] -> Dec input True
  ["dec", input] -> Dec input False
  _ -> Help

  -- TODO:
  -- $> e status file
  -- Found {} plain values to encrypt:
  --    a
  --    b
  --    c
  -- Found {} encrypted values:
  --    a
  --    b
  --    c
  -- Valid file.
