module Trace.Forward.Test.CCodec (diffFileSDUs, drvFileCBOR) where

import           "base" Prelude hiding (unzip)
-- This as-of-yet unused import reflects a goal to generalize from
-- monomorphic use of the IO monad to future monad-polymorphic
-- potentially pure use in the decoding functions.
import           "base" Control.Arrow (ArrowChoice (left))
import           "base" Control.Exception (assert)
import           "base" Control.Monad (forM_, join)
import           "base" Control.Monad.IO.Class (MonadIO (liftIO))
import           "base" Data.Function (on)
import           "base" Data.List.NonEmpty (NonEmpty ((:|)))
import           "base" Data.Maybe (fromJust)
import           "base" Debug.Trace (trace)
import           "base" Numeric (showHex)
import           "base" System.IO (Handle, IOMode (ReadMode), SeekMode (AbsoluteSeek, RelativeSeek, SeekFromEnd))
import qualified "base" System.IO as IO (hSeek, hTell, openFile)

import qualified "bytestring" Data.ByteString.Lazy as
  LBS (ByteString, hGet)

import           "cborg"      Codec.CBOR.Read (DeserialiseFailure (..))
import qualified "cborg"      Codec.CBOR.Read as
  CBOR (ByteOffset, deserialiseFromBytesWithSize)

import           "containers" Data.Map.Strict (Map)
import qualified "containers" Data.Map.Strict as
  Map ((!?), empty, insert, toList)
import           "containers" Data.Map.Merge.Strict as
  Map (SimpleWhenMatched, SimpleWhenMissing)
import qualified "containers" Data.Map.Merge.Strict as
  Map (mapMissing, merge, zipWithMatched)

import           "extra" Control.Monad.Extra (whenJustM, whileM)
import           "extra" Data.List.Extra (unsnoc)

import qualified "filepath" System.FilePath as FilePath (splitExtension)

import qualified "network-mux" Network.Mux.Codec as
  Mux (decodeSDU)
import qualified "network-mux" Network.Mux.Trace as
  Mux (Error (..))
import qualified "network-mux" Network.Mux.Types as
  Mux (MiniProtocolNum (..), RemoteClockModel (..), SDU (..), SDUHeader (..))

import           "these" Data.These (These (..))
import qualified "these" Data.These as These ()

import           "transformers" Control.Monad.Trans.Class (MonadTrans (lift))
import           "transformers" Control.Monad.Trans.Except (ExceptT (..))
import qualified "transformers" Control.Monad.Trans.Except as
  Except (mapExceptT, throwE)
import           "transformers" Control.Monad.Trans.RWS (RWST)
import qualified "transformers" Control.Monad.Trans.RWS as
  RWS (ask, gets, modify, runRWST)

import qualified "transformers-except" Control.Monad.Trans.Except.Extra as
  Except (hoistEither)

deriving instance Show Mux.RemoteClockModel
deriving instance Show Mux.SDUHeader
deriving instance Show Mux.SDU

data ParseCBOREnv = ParseCBOREnv
  { fileHandle :: Handle
  , fileSize   :: Integer
  } deriving (Eq, Show)

data ParseCBORState t = ParseCBORState
  { cborSDUs   :: Map Integer (Mux.SDUHeader, t)
  } deriving (Eq, Show)

type ParseCBORRWS t = RWST ParseCBOREnv () (ParseCBORState t) IO
type ParseCBORError = Mux.Error `Either` DeserialiseFailure
type ParseCBORMonad t = ExceptT ParseCBORError (ParseCBORRWS t)

evalParseCBORRWS :: forall t . () => ParseCBOREnv -> ParseCBORRWS t (Either ParseCBORError ()) -> IO (Either ParseCBORError (ParseCBORState t))
evalParseCBORRWS env monad = do
  (result, state, _)
    <- RWS.runRWST monad env ParseCBORState { cborSDUs = Map.empty }
  case result of
    Left e  -> pure $ Left e
    Right _ -> pure $ Right state

drvFileCBOR :: forall t . () => FilePath -> ExceptT ParseCBORError IO (ParseCBORState t)
drvFileCBOR filePath = do
  fileHandle <- liftIO do IO.openFile filePath ReadMode
  liftIO do IO.hSeek fileHandle SeekFromEnd 0
  fileSize <- liftIO do IO.hTell fileHandle
  liftIO do IO.hSeek fileHandle AbsoluteSeek 0
  evalParseCBORRWS ParseCBOREnv {..} `Except.mapExceptT` whileM parseFileCBOR

parseFileCBOR :: forall t . () => ParseCBORMonad t Bool
parseFileCBOR = do
  ParseCBOREnv {..} <- lift RWS.ask
  offset <- liftIO do IO.hTell fileHandle
  "entering parseFileCBOR at offset " <> show offset `traceOp` do
    whenJustM (lift $ RWS.gets ((Map.!? offset) . cborSDUs)) \_ -> do
      Except.throwE . Left . Mux.SDUDecodeError $ unwords
        ["parseFileSDUs", "repeated", "offset", show offset]
  Mux.SDU { msHeader = sduHdr@Mux.SDUHeader {..} } <- join $ liftIO do
    Except.hoistEither . left Left . Mux.decodeSDU <$> LBS.hGet fileHandle 8
  let newOffset = offset + 8 + fromIntegral mhLength
      decoderUnknown = undefined
  (_, _, cbor) :: (LBS.ByteString, CBOR.ByteOffset, t) <- (ExceptT (left Right . CBOR.deserialiseFromBytesWithSize decoderUnknown <$> ((liftIO do LBS.hGet fileHandle (fromIntegral mhLength)) :: ParseCBORRWS t LBS.ByteString)) :: ParseCBORMonad t (LBS.ByteString, CBOR.ByteOffset, t))
  newOffset' <- liftIO do IO.hTell fileHandle
  let exitMsg = "exiting parseFileCBOR at newOffset "
                    <> show (newOffset, newOffset')
  exitMsg `trace` assert (newOffset == newOffset') do
    lift $ RWS.modify \state@ParseCBORState {..} -> state { cborSDUs = offset `Map.insert` (sduHdr, cbor) $ cborSDUs }
    pure $ newOffset < fileSize

data ParseSDUEnv = ParseSDUEnv
  { fileHandle :: Handle
  , fileSize   :: Integer }
  deriving (Eq, Show)

type ParseSDUState = Map Integer Mux.SDUHeader
type CombinedSDUState = Map Integer (These Mux.SDUHeader Mux.SDUHeader)
type ParseSDURWS = RWST ParseSDUEnv () ParseSDUState IO
type ParseSDUMonad = ExceptT Mux.Error ParseSDURWS

cmpFileSDUs :: FilePath -> FilePath -> ExceptT Mux.Error IO CombinedSDUState
cmpFileSDUs = liftA2 mergeThese `on` drvFileSDUs

evalParseSDURWS :: ParseSDUEnv -> ParseSDURWS (Either Mux.Error ()) -> IO (Either Mux.Error ParseSDUState)
evalParseSDURWS env monad = do
  (result, state, _) <- RWS.runRWST monad env Map.empty
  case result of
    Left e  -> pure $ Left e
    Right _ -> pure $ Right state

drvFileSDUs :: FilePath -> ExceptT Mux.Error IO ParseSDUState
drvFileSDUs filePath = do
  fileHandle <- liftIO do IO.openFile filePath ReadMode
  liftIO do IO.hSeek fileHandle SeekFromEnd 0
  fileSize <- liftIO do IO.hTell fileHandle
  liftIO do IO.hSeek fileHandle AbsoluteSeek 0
  evalParseSDURWS ParseSDUEnv {..} `Except.mapExceptT` whileM parseFileSDUs

parseFileSDUs :: ParseSDUMonad Bool
parseFileSDUs = do
  ParseSDUEnv {..} <- lift RWS.ask
  offset <- liftIO do IO.hTell fileHandle
  "entering parseFileSDUs at offset " <> show offset `traceOp` do
    whenJustM (lift $ RWS.gets (Map.!? offset)) \_ -> do
      Except.throwE . Mux.SDUDecodeError $ unwords
        ["parseFileSDUs", "repeated", "offset", show offset]
  Mux.SDU { msHeader = sduHdr@Mux.SDUHeader {..} } <- join $ liftIO do
    Except.hoistEither . Mux.decodeSDU <$> LBS.hGet fileHandle 8
  let newOffset = offset + 8 + fromIntegral mhLength
  liftIO do IO.hSeek fileHandle RelativeSeek $ fromIntegral mhLength
  newOffset' <- liftIO do IO.hTell fileHandle
  let exitMsg = "exiting parseFileSDUs at newOffset "
                    <> show (newOffset, newOffset')
  exitMsg `trace` assert (newOffset == newOffset') do
    lift . RWS.modify $ offset `Map.insert` sduHdr
    pure $ newOffset < fileSize

showHex' :: Integral int => int -> String
showHex' int = "0x" <> showHex int ""

deriving instance Eq Mux.SDUHeader

cmpShowSDUs :: String -> String -> Integer
  -> These Mux.SDUHeader Mux.SDUHeader -> NonEmpty String
cmpShowSDUs label1 label2 offset = \case
  This sdu -> ((label1 <> ": ") <>) <$> printSDU sdu offset
  That sdu -> ((label2 <> ": ") <>) <$> printSDU sdu offset
  These sdu1 sdu2
    | sdu1 /= sdu2
    , offsetLine :| rest1 <- printSDU sdu1 offset
    , _          :| rest2 <- printSDU sdu2 offset
    -> ("sdu1 /= sdu2 " <> offsetLine)
         :| (((label1 <> ": ") <>) <$> rest1)
         <> (((label2 <> ": ") <>) <$> rest2)
    | otherwise
    , offsetLine :| rest <- printSDU sdu1 offset
    -> ("sdu1 == sdu2 " <> offsetLine) :| rest

mapMissing' :: (t -> t') -> SimpleWhenMissing k t t'
mapMissing' = Map.mapMissing . const

zipWithMatched' :: (t -> t' -> t'') -> SimpleWhenMatched k t t' t''
zipWithMatched' = Map.zipWithMatched . const

infixr 3 `mergeThese`
mergeThese :: Map Integer t -> Map Integer t' -> Map Integer (These t t')
mergeThese = Map.merge (mapMissing' This) (mapMissing' That) $ zipWithMatched' These

traceBrackets :: Monad monad => String -> monad t -> monad t
name `traceBrackets` action = do
  unwords ["begin", name] `trace` pure ()
  x <- action
  unwords ["finish", name] `trace` pure x

infixr 1 `traceOp`
traceOp :: String -> t -> t
s `traceOp` x = s `trace` x

diffFileSDUs :: FilePath -> FilePath -> ExceptT Mux.Error IO ()
diffFileSDUs filePath1 filePath2
  | (_, '.' : label1) <- FilePath.splitExtension filePath1
  , (_, '.' : label2) <- FilePath.splitExtension filePath2
  = unwords ["diffFileSDUs", filePath1, filePath2] `traceBrackets` do
       diff <- Map.toList <$> (filePath1 `cmpFileSDUs` filePath2)
       "past cmpFileSDUs" `trace` pure ()
       liftIO do forM_ diff \(off, theseSDUs) -> do
                   flip trace (pure ()) $ "begin SDU at off " <> show off
                   mapM_ putStrLn $ cmpShowSDUs label1 label2 off theseSDUs
                   flip trace (pure ()) $ "finish SDU at off " <> show off
  | otherwise
  = Except.throwE . Mux.SDUDecodeError
  $ unwords [ "bad filenames", filePath1, filePath2 ]

printSDU :: Mux.SDUHeader -> Integer -> NonEmpty String
printSDU Mux.SDUHeader {..} offset = is''' where
  Mux.MiniProtocolNum mhNum' = mhNum
  is''' :: NonEmpty String
  is''' = ("SDU header at off=" <> showHex' offset) :| is''
  is'' :: [String]
  is'' | (frontList, backElt) <- fromJust $ unsnoc is'
       = [ "struct sdu {" ] <> frontList <> [ backElt <> " };" ]
  is'  :: [String]
  is'  = ("\t" <>) . (<> ";") . unwords <$> is
  is   :: [[String]]
  is   = [ [ "uint32_t", "sdu_xmit", "="
             , showHex' $ Mux.unRemoteClockModel mhTimestamp ]
        , [ "uint16_t sdu_proto_num", "="
             , show mhNum', "(" <> showHex' mhNum' <> ")" ]
        , [ "uint16_t sdu_len", "="
             , show mhLength, "(" <> showHex' mhLength <> ")" ]
        , [ "bool", "sdu_init_or_resp", "=", show mhDir ]
        , [ "const", "char", "*sdu_data", "=", "(nil)" ] ]
