{-# Language BangPatterns #-}
{-# Language OverloadedStrings #-}
import Data.Semigroup

import Criterion.Main

import Tem ()
import E

main :: IO ()
main = defaultMain suite

suite :: [Benchmark]
suite =
  [ bgroup "decode . encode"
    [ bench "1K" $ nf proc (tem 1000)
    , bench "2K" $ nf proc (tem 2000)
    ]
  ]

proc :: Tem -> Maybe Tem
proc !t = decode (encode t)
{-# INLINE proc #-}

tem :: Int -> Tem
tem i | i <= 0 = Nil
      | otherwise
  =  txt "Criterion is a statistically aware benchmarking tool."
  <> val (PlainValue (ValName "criterion") (AlgName "is") (arg (ArgName "statically") (ArgValue "aware")) (PlainContent "benchmarking tool.\n"))
  <> ref (ValRef (ValName "okay"))
  <> tem (i - 1)
