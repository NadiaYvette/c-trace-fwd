module Main (main) where
import qualified "base" Data.List as
  List (isPrefixOf)
import qualified "directory" System.Directory as
  Dir (listDirectory)

import           "filepath" System.FilePath ((</>))
import qualified "filepath" System.FilePath as
  FilePath (splitFileName)

import qualified "optparse-applicative" Options.Applicative as
  Options (Completer, Parser, ParserInfo, completer, execParser
          , fullDesc, info, mkCompleter, strArgument)

import qualified "trace-compare" Trace.Forward.Test.CCodec as
  CCodec (diffFileSDUs)

import qualified "transformers-except" Control.Monad.Trans.Except.Extra as
  Except (exceptT)

tcComplete :: Options.Completer
tcComplete = Options.mkCompleter \(FilePath.splitFileName -> (dir, pfx)) -> do
  dirEnts <- Dir.listDirectory dir
  pure $ [dir </> d | d <- dirEnts, pfx `List.isPrefixOf` d]

tcInfo :: Options.ParserInfo (FilePath, FilePath)
tcInfo = Options.info options Options.fullDesc

options :: Options.Parser (FilePath, FilePath)
options = do
  path1 <- Options.strArgument $ Options.completer tcComplete
  path2 <- Options.strArgument $ Options.completer tcComplete
  pure (path1, path2)

main :: IO ()
main = do
  (path1, path2) <- Options.execParser tcInfo
  Except.exceptT print pure $ path1 `CCodec.diffFileSDUs` path2
