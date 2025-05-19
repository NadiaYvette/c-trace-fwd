module Trace.Forward.Test.CCodec
  ( handshakeCodec
  , decodeHandshake
  , cmpFileOffsetsSDU
  , cmpFileSDUs
  , cmpShowSDUs
  , decodeToken
  , diffFileSDUs
  , parseHandshakeLog
  , parseSDU
  , printSDU
  , printSDUallOffsets
  ) where

import           "base" Prelude hiding (unzip)
import           "base" Control.Arrow (ArrowChoice (..))
-- This as-of-yet unused import reflects a goal to generalize from
-- monomorphic use of the IO monad to future monad-polymorphic
-- potentially pure use in the decoding functions.
import           "base" Control.Exception (IOException, throw)
import           "base" Control.Monad (forM, forM_)
import           "base" Control.Monad.IO.Class (MonadIO (liftIO))
import           "base" Data.Function (on)
import           "base" Data.Functor ((<&>))
import           "base" Data.Kind (Type)
import           "base" Data.List.NonEmpty (NonEmpty ((:|)))
import qualified "base" Data.List.NonEmpty as NonEmpty (head)
import           "base" Data.Maybe (fromJust)
import           "base" Debug.Trace (trace)
import           "base" GHC.Generics (Generic (..))
import           "base" Numeric (showHex)
import           "base" System.IO (Handle, IOMode (..), SeekMode (..))
import qualified "base" System.IO as IO (hSeek, hTell, openFile)

import qualified "bytestring" Data.ByteString.Lazy as
  LBS (ByteString, hGet, readFile, splitAt)

import qualified "cborg" Codec.CBOR.Read as CBOR (DeserialiseFailure)
import qualified "cborg" Codec.CBOR.Term as CBOR (Term)

import           "composition-extra" Data.Functor.Syntax ((<$$>), (<$$$>))

import           "containers" Data.Map.Strict (Map)
import qualified "containers" Data.Map.Strict as
  Map (fromList, toList)
import           "containers" Data.Map.Merge.Strict as
  Map (SimpleWhenMatched, SimpleWhenMissing)
import qualified "containers" Data.Map.Merge.Strict as
  Map (mapMissing, merge, zipWithMatched)
import           "containers" Data.Set as
  Set (Set)
import qualified "containers" Data.Set as
  Set (insert, member)

import           "extra" Control.Monad.Extra (maybeM)
import           "extra" Data.Either.Extra (eitherToMaybe, fromEither)
import           "extra" Data.List.Extra (intersperse, unsnoc)
import           "extra" Data.Tuple.Extra (both, swap)

import qualified "filepath" System.FilePath as FilePath (splitExtension)

import           "io-classes-mtl" Control.Monad.Class.MonadThrow.Trans ()
import           "io-classes" Control.Monad.Class.MonadThrow (MonadCatch (..))

import qualified "network-mux" Network.Mux.Codec as
  Mux (decodeSDU)
import qualified "network-mux" Network.Mux.Trace as
  Mux (Error (..), handleIOException)
import qualified "network-mux" Network.Mux.Types as
  Mux (MiniProtocolNum (..), RemoteClockModel (..), SDU (..), SDUHeader (..))

import           "ouroboros-network-framework" Ouroboros.Network.Protocol.Handshake.Codec as
  Ouroboros (codecHandshake)
import           "ouroboros-network-framework" Ouroboros.Network.Protocol.Handshake.Type as
  Ouroboros (Handshake (..), SingHandshake (..))

import           "these" Data.These (These (..))
import qualified "these" Data.These as These ()

import           "trace-dispatcher" Cardano.Logging.Version as
  Trace (ForwardingVersion, forwardingVersionCodec)

import           "transformers" Control.Monad.Trans.Class (MonadTrans (lift))
import           "transformers" Control.Monad.Trans.Except (ExceptT)
import qualified "transformers" Control.Monad.Trans.Except as
  Except (except, handleE, mapExceptT, runExceptT, throwE, tryE)
import           "transformers" Control.Monad.Trans.RWS (RWST)
import qualified "transformers" Control.Monad.Trans.RWS as
  RWS (ask, modify, tell)

import           "typed-protocols" Network.TypedProtocol.Codec (Codec (..), DecodeStep (..), SomeMessage (..), runDecoder)
import           "typed-protocols" Network.TypedProtocol.Core (IsActiveState (..), Protocol (..))

handshakeCodec :: forall
      (error :: Type)
      (handshake :: Type)
      (monad :: Type -> Type)
      (string :: Type)
      (term :: Type)
      . ()
  => error ~ CBOR.DeserialiseFailure
  => handshake ~ Handshake ForwardingVersion term
  => monad ~ IO
  => string ~ LBS.ByteString
  => term ~ CBOR.Term
  => Codec handshake error monad string
handshakeCodec = codecHandshake forwardingVersionCodec

parseSDU :: LBS.ByteString -> Either Mux.Error (Mux.SDU, LBS.ByteString)
parseSDU (LBS.splitAt 8 -> (sduBS, bs))
  = right (, bs) $ Mux.decodeSDU sduBS

deriving instance Show Mux.RemoteClockModel
deriving instance Show Mux.SDUHeader
deriving instance Show Mux.SDU

decodeHandshake :: forall (error :: Type)
                          (vNumber :: Type)
                          (vParams :: Type)
                          (st :: Handshake vNumber vParams)
                          (string :: Type)
                        . ()
  => error ~ CBOR.DeserialiseFailure
  => vNumber ~ ForwardingVersion
  => vParams ~ CBOR.Term
  => string ~ LBS.ByteString
  => IsActiveState st (StateAgency st)
  => SingHandshake st
       -> IO (DecodeStep string error IO (SomeMessage st))
decodeHandshake = decode handshakeCodec

decodePropose :: forall (error :: Type)
                        (vNumber :: Type)
                        (vParams :: Type)
                        (stPropose :: Handshake vNumber vParams)
                        (string :: Type)
                      . ()
  => error ~ CBOR.DeserialiseFailure
  => vNumber ~ ForwardingVersion
  => vParams ~ CBOR.Term
  => stPropose ~ 'StPropose
  => string ~ LBS.ByteString
  => IsActiveState stPropose (StateAgency stPropose)
  => IO (DecodeStep string error IO (SomeMessage stPropose))
decodePropose = decodeHandshake SingPropose

decodeConfirm :: forall (error :: Type)
                        (vNumber :: Type)
                        (vParams :: Type)
                        (stConfirm :: Handshake vNumber vParams)
                        (string :: Type)
                      . ()
  => error ~ CBOR.DeserialiseFailure
  => vNumber ~ ForwardingVersion
  => vParams ~ CBOR.Term
  => stConfirm ~ 'StConfirm
  => string ~ LBS.ByteString
  => IsActiveState stConfirm (StateAgency stConfirm)
  => IO (DecodeStep string error IO (SomeMessage stConfirm))
decodeConfirm = decodeHandshake SingConfirm

decodeDone :: forall (error :: Type)
                     (vNumber :: Type)
                     (vParams :: Type)
                     (stDone :: Handshake vNumber vParams)
                     (string :: Type)
                   . ()
  => error ~ CBOR.DeserialiseFailure
  => vNumber ~ ForwardingVersion
  => vParams ~ CBOR.Term
  => stDone ~ 'StDone
  => string ~ LBS.ByteString
  => IsActiveState stDone (StateAgency stDone)
  => IO (DecodeStep string error IO (SomeMessage stDone))
decodeDone = decodeHandshake SingDone

data Either3 t t' t''
  = Left3 t
  | Middle3 t'
  | Right3 t''
  deriving (Eq, Foldable, Generic, Ord, Read, Show)

decodeToken :: forall (error :: Type)
                       (vNumber :: Type)
                       (vParams :: Type)
                       (stConfirm :: Handshake vNumber vParams)
                       (stDone :: Handshake vNumber vParams)
                       (stPropose :: Handshake vNumber vParams)
                       (string :: Type)
                     . ()
  => error ~ CBOR.DeserialiseFailure
  => vNumber ~ ForwardingVersion
  => vParams ~ CBOR.Term
  => stConfirm ~ 'StConfirm
  => IsActiveState stConfirm (StateAgency stConfirm)
  => stDone ~ 'StDone
  => IsActiveState stDone (StateAgency stDone)
  => stPropose ~ 'StPropose
  => IsActiveState stPropose (StateAgency stPropose)
  => string ~ LBS.ByteString
  => [string]
     -> IO ( Either error (SomeMessage stConfirm)
           , Either error (SomeMessage stDone)
           , Either error (SomeMessage stPropose))
decodeToken bytes = do
  confirm <- runDecoder bytes =<< decodeConfirm
  done    <- runDecoder bytes =<< decodeDone
  propose <- runDecoder bytes =<< decodePropose
  pure (confirm, done, propose)

parseHandshakeLog :: FilePath -> IO ()
parseHandshakeLog logFile = parseSDU <$> LBS.readFile logFile >>= \case
  Left msg -> print msg
  Right (sdu, cborBS) -> do
    print sdu
    print . take 1024 $ show cborBS
    pure ()

handleMuxIO :: MonadCatch monad
  => String -> ExceptT IOException monad t -> ExceptT error monad t
handleMuxIO msg = Except.handleE $ Mux.handleIOException msg

hSize :: Handle -> IO Integer
hSize fileHandle = do
  savedOffset <- IO.hTell fileHandle
  IO.hSeek fileHandle SeekFromEnd 0
  endOffset <- IO.hTell fileHandle
  IO.hSeek fileHandle AbsoluteSeek savedOffset
  pure endOffset

preadLBS :: Handle -> Integer -> Int -> ExceptT Mux.Error IO LBS.ByteString
preadLBS fileHandle offset count = do
  endOffset <- "checking size" `handleMuxIO` liftIO do hSize fileHandle
  if offset + fromIntegral count >= endOffset
    then Except.throwE . Mux.SDUDecodeError
                $ unwords ["offset + count", show $ offset + fromIntegral count, " >= EOF", show endOffset]
    else "doing read" `handleMuxIO` liftIO do
      savedOffset <- IO.hTell fileHandle
      IO.hSeek fileHandle AbsoluteSeek offset
      byteString <- LBS.hGet fileHandle count
      IO.hSeek fileHandle AbsoluteSeek savedOffset
      pure byteString

parseSDUatOffset :: Handle -> Integer -> Int -> ExceptT Mux.Error IO Mux.SDU
parseSDUatOffset fileHandle offset count = do
  byteString <- preadLBS fileHandle offset count
  Except.except $ fst <$> parseSDU byteString

-- | A monadic unfold.
unfoldM :: Monad m => (s -> m (Maybe (a, s))) -> s -> m [a]
unfoldM f s = do
    f s >>= maybe (pure []) \(a, s') -> (a :) <$> unfoldM f s'

loopM' :: Monad monad => monad (Maybe t) -> monad [t]
loopM' action = flip (maybeM $ pure []) action $ pure . (:[])

parseFileSDUs' :: ExceptT Mux.Error (RWST Handle [(Mux.SDUHeader, Integer)] (Set Integer) IO) Bool
parseFileSDUs' = do
  fileHandle <- lift RWS.ask
  offset <- liftIO do IO.hTell fileHandle
  Mux.SDU{..}
    <- Except.mapExceptT liftIO $ parseSDUatOffset fileHandle offset 8
  let sduH@Mux.SDUHeader{..} = msHeader
  lift do
    RWS.modify $ Set.insert offset
    RWS.tell [(sduH, offset)]
  let newOffset = offset + 8 + fromIntegral mhLength
  fileSize <- liftIO do hSize fileHandle
  if newOffset >= fileSize
    then pure False
    else liftIO do
      -- Since the content isn't being touched here:
      IO.hSeek fileHandle RelativeSeek newOffset
      pure True

parseFileSDUs :: FilePath -> ExceptT Mux.Error IO [(Mux.SDUHeader, Integer)]
parseFileSDUs filePath = unwords ["parseFileSDUs", filePath] `traceBrackets` do
  fileHandle <- liftIO do IO.openFile filePath ReadMode
  flip unfoldM 0 \(offset :: Integer) -> unwords ["offset", show offset] `traceBrackets` do
    maybeSDUH <- fmap eitherToMaybe . Except.tryE $
      Mux.msHeader <$> parseSDUatOffset fileHandle offset 8
    pure $ maybeSDUH <&> \sduH@Mux.SDUHeader {..} ->
      let newOffset = offset + fromIntegral mhLength
       in ((sduH, offset), newOffset)

fileOffsetsSDU :: FilePath -> ExceptT Mux.Error IO [Integer]
fileOffsetsSDU filePath = snd <$$> parseFileSDUs filePath

showHex' :: Integral int => int -> String
showHex' int = "0x" <> showHex int ""

unzip :: Functor functor => functor (t, t') -> (functor t, functor t')
unzip structure = (fst <$> structure, snd <$> structure)

bothFoldr1 :: forall (fold :: Type -> Type) (t :: Type) . ()
  => Foldable fold
  => Functor fold
  => (t -> t -> t) -> fold (t, t) -> (t, t)
bothFoldr1 op struct = (foldr1 op leftStruct, foldr1 op rightStruct) where
  (leftStruct, rightStruct) :: (fold t, fold t) = unzip struct

pad :: Int -> String -> String
pad w s = replicate (w - length s) ' ' <> s

showOffsetPairs :: forall (offset :: Type) . ()
  => Integral offset
  => String -> String -> [(offset, offset)] -> [String]
showOffsetPairs ((<>":")->labelA) ((<>":")->labelB) pairList = strings where
  pairList' :: [(String, String)] = both showHex' <$> pairList
  (maxA, maxB) :: (Int, Int) = bothFoldr1 max $ both length <$> pairList'
  strings = forM pairList' \(pad maxA -> a, pad maxB -> b) -> do
    unwords [labelA, a, labelB, b]

zipDropEqOnM :: (Monad monad, Eq t')
  => (t -> monad [t']) -> t -> t -> monad [(t', t')]
zipDropEqOnM f x y = dropWhile (uncurry (==)) <$> liftA2 zip (f x) (f y)

cmpFileOffsetsSDU :: FilePath -> FilePath -> ExceptT Mux.Error IO ()
cmpFileOffsetsSDU filePath1 filePath2
  | (_, label1) <- FilePath.splitExtension filePath1
  , (_, label2) <- FilePath.splitExtension filePath2
  = liftIO . mapM_ putStrLn . showOffsetPairs label1 label2
            =<< zipDropEqOnM fileOffsetsSDU filePath1 filePath2

cmpFileSDUs :: FilePath -> FilePath -> ExceptT Mux.Error IO (Map Integer (These Mux.SDUHeader Mux.SDUHeader))
cmpFileSDUs = liftA2 mergeThese `on` mapOfFile where
  mapOfFile f = Map.fromList <$> swap <$$> parseFileSDUs f

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
    -> ("sdu1 == sdu2" <> offsetLine) :| rest

mapMissing' :: (t -> t') -> SimpleWhenMissing k t t'
mapMissing' = Map.mapMissing . const

zipWithMatched' :: (t -> t' -> t'') -> SimpleWhenMatched k t t' t''
zipWithMatched' = Map.zipWithMatched . const

mergeThese :: Map Integer t -> Map Integer t' -> Map Integer (These t t')
mergeThese = Map.merge (mapMissing' This) (mapMissing' That) $ zipWithMatched' These

traceBrackets :: Monad monad => String -> monad t -> monad t
name `traceBrackets` action = do
  unwords ["begin", name] `trace` pure ()
  x <- action
  unwords ["finish", name] `trace` pure x

traceM :: Applicative apply => String -> t -> apply t
s `traceM` x = s `trace` pure x

traceAct :: Applicative apply => String -> apply ()
traceAct = (`traceM` ())

diffFileSDUs :: FilePath -> FilePath -> ExceptT Mux.Error IO ()
diffFileSDUs filePath1 filePath2
  | (_, '.' : label1) <- FilePath.splitExtension filePath1
  , (_, '.' : label2) <- FilePath.splitExtension filePath2
  = unwords ["diffFileSDUs", filePath1, filePath2] `traceBrackets` do
       diff <- Map.toList <$> (filePath1 `cmpFileSDUs` filePath2)
       traceAct "past cmpFileSDUs"
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

printSDUallOffsets :: FilePath -> IO ()
printSDUallOffsets filePath = fromEither . left throw <$> Except.runExceptT do
  sdus :: [(Mux.SDUHeader, Integer)] <- parseFileSDUs filePath
  let sduLines :: [NonEmpty String]
      sduLines = uncurry printSDU <$> sdus
      cutLines :: [String]
      cutLines = intersperse "" $ NonEmpty.head <$> sduLines
  forM_ cutLines $ liftIO . putStrLn
