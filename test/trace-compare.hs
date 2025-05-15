{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -Wno-error=unused-imports
                -Wno-error=unused-local-binds
                -Wno-error=unused-matches
                -Wno-error=partial-type-signatures
                -Wno-error=unused-top-binds #-}

module Main (main) where
import qualified Control.Monad.Trans.Except.Extra as Except (exceptT)
import qualified Trace.Forward.Test.CCodec as CCodec (diffFileSDUs)
import qualified System.Environment as Env (getArgs)

main :: IO ()
main = Env.getArgs >>= \case
  [path1, path2] ->
    Except.exceptT print pure $ CCodec.diffFileSDUs path1 path2
  _ -> putStrLn "Usage: trace-compare FILE1 FILE2"
