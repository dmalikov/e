module Main (main) where

import           Args               (parseArgs)
import           Run                (run)
import           System.Environment (getArgs)

main :: IO ()
main = run . parseArgs =<< getArgs
