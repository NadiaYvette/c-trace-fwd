module Main (main) where
import qualified "base" Data.List as
  List (isPrefixOf)
import qualified "directory" System.Directory as
  Dir (listDirectory)

import           "filepath" System.FilePath ((</>))
import qualified "filepath" System.FilePath as
  FilePath (splitFileName)

import qualified "optparse-applicative" Options.Applicative as
  Options (ArgumentFields, Completer, InfoMod, Mod, Parser, ParserInfo
          , completer, execParser, info, metavar, mkCompleter, progDesc
          , strArgument)

import qualified "trace-compare" Trace.Forward.Test.CCodec as
  CCodec (diffFileSDUs)

import qualified "transformers-except" Control.Monad.Trans.Except.Extra as
  Except (exceptT)

tcComplete :: Options.Completer
tcComplete = Options.mkCompleter \(FilePath.splitFileName -> (dir, pfx)) -> do
  dirEnts <- Dir.listDirectory dir
  pure [dir </> ent | ent <- dirEnts, pfx `List.isPrefixOf` ent]

tcInfo :: Options.ParserInfo (FilePath, FilePath)
tcInfo = options `Options.info` tcInfoMod

tcInfoMod :: Options.InfoMod (FilePath, FilePath)
tcInfoMod = Options.progDesc "compare trace SDU decodings"

tcMod :: Bool -> Options.Mod Options.ArgumentFields FilePath
tcMod b = Options.completer tcComplete <> Options.metavar txt where
  txt = "FILE" <> if not b then "1" else "2"

options :: Options.Parser (FilePath, FilePath)
options = do
  path1 <- Options.strArgument $ tcMod False
  path2 <- Options.strArgument $ tcMod True
  pure (path1, path2)

main :: IO ()
main = do
  (path1, path2) <- Options.execParser tcInfo
  Except.exceptT print pure $ path1 `CCodec.diffFileSDUs` path2
