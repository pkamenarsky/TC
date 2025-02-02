import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Internal as B

import System.Environment

import Debug.Trace

import Data.Time.Format
import Data.Time.LocalTime
import Data.Time.Clock
import Data.Time.Clock.POSIX

import System.Locale

import Control.Applicative

import qualified Data.PQueue.Min as PQ

import Data.Maybe
import Data.List
import Data.Binary
import qualified Data.Binary.Strict.Get as SG
import qualified Data.Binary.Strict.BitGet as BG
import Data.Void
import Data.Word (Word8, Word16, Word32)

import Foreign.C.String (CString, peekCString, withCString)
import Foreign.Ptr (Ptr, plusPtr, nullPtr, FunPtr, freeHaskellFunPtr)
import Foreign.C.Types (CInt, CUInt, CChar, CUChar, CLong)
import Foreign.Marshal.Alloc (alloca, allocaBytes, free)
import Foreign.Marshal.Array (allocaArray, peekArray)

import Control.Pipe
import Control.Pipe.Final
import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.IO.Class

import qualified Network.Pcap as PC
import Network.Pcap.Base

import Numeric (showHex)

import Test.QuickCheck

-- pcap

type ErrBuf = Ptr CChar

foreign import ccall unsafe pcap_open_offline :: CString -> ErrBuf -> IO (Ptr PcapTag)
foreign import ccall unsafe pcap_close :: Ptr PcapTag -> IO ()

withErrBuf :: (a -> Bool) -> (ErrBuf -> IO a) -> IO a
withErrBuf isError f = allocaArray (256) $ \errPtr -> do
    ret <- f errPtr
    if isError ret
      then peekCString errPtr >>= ioError . userError
      else return ret

openPcap :: FilePath -> IO (Ptr PcapTag)
openPcap name = withCString name $ \namePtr -> do
	withErrBuf (== nullPtr) (pcap_open_offline namePtr)

closePcap :: Ptr PcapTag -> IO ()
closePcap = pcap_close
 
toBS :: (PktHdr, Ptr Word8) -> IO (PktHdr, B.ByteString)
toBS (hdr, ptr) = do
    let len = hdrCaptureLength hdr
    s <- B.create (fromIntegral len) $ \p -> B.memcpy p ptr (fromIntegral len)
    return (hdr, s)

-- pcap Frames

readNextF :: Ptr PcapTag -> Ensure () (PktHdr, BS.ByteString) IO ()
readNextF h = do
	packet@(hdr, _) <- lift $ next h
	case hdr of
		PktHdr 0 0 0 0 -> return ()
		_ -> do
			lift (toBS packet) >>= yieldF
			readNextF h

readPcapF :: FilePath -> Frame () (PktHdr, BS.ByteString) IO ()
readPcapF name = Frame $ close $ do
	-- lift $ print "Opening file"
	h <- lift $ openPcap name
	-- finallyP (closePcap h >> print "Closing file") (readNextF h)
	finallyP (closePcap h) (readNextF h)

-- UDP

data Ethernet = Ethernet {ether_dhost :: [Word8], ether_shost :: [Word8], ether_type :: Word16} deriving Show
data Ip = Ip {ip_vhl :: Word8, ip_tos :: Word8, ip_len :: Word16, ip_id :: Word16, ip_off :: Word16,
	ip_ttl :: Word8, ip_p :: Word8, ip_sum :: Word16, ip_src :: Word32, ip_dst :: Word32} deriving Show
data Udp = Udp {udp_sport :: Word16, udp_dport :: Word16, udp_length :: Word16, udp_csum :: Word16, udp_payload :: [Word8]} deriving Show

parseEthernetFrame :: SG.Get Ethernet
parseEthernetFrame = do
	ether_dhost <- replicateM 6 SG.getWord8
	ether_shost <- replicateM 6 SG.getWord8
	ether_type <- SG.getWord16be
	return $ Ethernet ether_dhost ether_shost ether_type

parseIpFrame :: SG.Get Ip
parseIpFrame = do
	ip_vhl <- SG.getWord8
	ip_tos <- SG.getWord8
	ip_len <- SG.getWord16be
	ip_id <- SG.getWord16be
	ip_off <- SG.getWord16be
	ip_ttl <- SG.getWord8
	ip_p <- SG.getWord8
	ip_sum <- SG.getWord16be
	ip_src <- SG.getWord32be
	ip_dst <- SG.getWord32be
	return $ Ip ip_vhl ip_tos ip_len ip_id ip_off ip_ttl ip_p ip_sum ip_src ip_dst

parseUDPFrame :: SG.Get Udp
parseUDPFrame = do
	udp_sport <- SG.getWord16be
	udp_dport <- SG.getWord16be
	udp_length <- SG.getWord16be
	udp_csum <- SG.getWord16be
	udp_payload <- replicateM ((fromIntegral udp_length) - 8) SG.getWord8
	return $ Udp udp_sport udp_dport udp_length udp_csum udp_payload

-- QPackets

data Bid = Bid {bid_price :: String, bid_quant :: String} deriving Show
data Ask = Ask {ask_price :: String, ask_quant :: String} deriving Show

data QPacket = QPacket {q_dtype :: String, q_itype :: String, q_mtype :: String, q_icode :: String,
	q_isno :: String, q_mstype :: String, q_tbid :: String, q_bids :: [Bid], q_task :: String, q_asks :: [Ask], q_accept :: String} deriving Show

tstr = map (toEnum . fromEnum)

parsee :: [Int] -> [Word8] -> [[Word8]]
parsee intervals bytes = fst $ foldl (\(list, bytes) x -> let (w, bytes') = splitAt x bytes in (list ++ [w], bytes')) ([], bytes) intervals

parseBid :: [Word8] -> Bid
parseBid bytes = let [price, quant] = map tstr $ parsee [5, 7] bytes in
	Bid price quant

parseAsk :: [Word8] -> Ask
parseAsk bytes = let [price, quant] = map tstr $ parsee [5, 7] bytes in
	Ask price quant

parseQPacket :: [Word8] -> QPacket
parseQPacket bytes = let
	parseMany n f b = map f $ parsee (replicate n 12) b
	parsed@[_, _, _, _, _, _, _, bids, _, asks, _, _] = parsee [2, 2, 1, 12, 3, 2, 7, 60, 7, 60, 50, 8] bytes
	[q_dtype, q_itype, q_mtype, q_icode, q_isno, q_mstype, q_tbid, _, q_task, _, _, q_accept] = map tstr parsed in
		QPacket q_dtype q_itype q_mtype q_icode q_isno q_mstype q_tbid (parseMany 5 parseBid bids) q_task (parseMany 5 parseAsk asks) q_accept

-- Frame combinators

printerF :: (Show a) => Frame a Void IO r
printerF = Frame $ forever $ do
	x <- awaitF
	lift $ print x

take' :: Int -> Frame a a IO ()
take' n
   | n < 1 = Frame $ close $ return ()
   | otherwise = Frame $ do
         replicateM_ (n - 1) $ do
             x <- awaitF
             yieldF x
         x <- awaitF
         close $ do
             yieldF x

mapF :: (Monad m) => (a -> b) -> Frame a b m r
mapF f = Frame $ forever $ do
	x <- awaitF
	yieldF $ f x

sortAccumF :: Monad m => Ord a => (a -> a -> Bool) -> PQ.MinQueue a -> Ensure a a m ()
sortAccumF f q
	| PQ.null q = do
		n <- awaitF
		sortAccumF f $ PQ.singleton n
	| otherwise = do
		n <- await
		let x = PQ.findMin q
		case n of
			Nothing -> mapM_ yieldF $ PQ.toAscList q
			Just n' -> if f x n'
				then do
					yieldF x
					sortAccumF f $ PQ.insert n' $ PQ.deleteMin q
				else
					sortAccumF f $ PQ.insert n' q

sortF :: Monad m => Ord a => (a -> a -> Bool) -> Frame a a m r
sortF f = Frame $ forever $ sortAccumF f PQ.empty

replicateF :: (Monad m) => Int -> a -> Frame () a m ()
replicateF n x = Frame $ close $ replicateM_ n $ yieldF x

filterF :: (Monad m) => (a -> Bool) -> Frame a a m ()
filterF f = Frame $ forever $ do
	x <- awaitF
	when (f x) $ yieldF x

-- Time

parsePacketTime :: PktHdr -> Int
parsePacketTime header = let
	secs = fromIntegral $ hdrSeconds header
	usecs = fromIntegral $ hdrUseconds header in
		secs * 1000 + usecs `div` 1000

parseQPacketTime :: String -> Int
parseQPacketTime str = let
	(timestr, uustr) = splitAt 6 str
	(Just local) = parseTime defaultTimeLocale "%Y%m%d%H%M%S" ("20110216" ++ timestr)
	secs = floor $ utcTimeToPOSIXSeconds $ localTimeToUTC (hoursToTimeZone 9) local
	(uu, _):_ = reads uustr :: [(Int, String)] in
		secs * 1000 + uu * 10

-- Packet

data Packet = Packet {p_time :: Int, p_qtime :: Int, p_qpacket :: QPacket}

instance Show Packet where
	show (Packet t qt qp) =
		show t ++ " " ++
		show qt ++ " " ++
		q_icode qp ++ " " ++
		(concat $ intersperse " " $ map (\bid -> bid_quant bid ++ "@" ++ bid_price bid) (reverse $ q_bids qp)) ++ " " ++
		(concat $ intersperse " " $ map (\ask -> ask_quant ask ++ "@" ++ ask_price ask) (q_asks qp))

instance Eq Packet where
	(==) p1 p2 = p_qtime p1 == p_qtime p2 && p_time p1 == p_time p2

instance Ord Packet where
	compare p1 p2
		| p_qtime p1 == p_qtime p2 = compare (p_time p1) (p_time p2)
		| otherwise = compare (p_qtime p1) (p_qtime p2)

processPacket :: (PktHdr, BS.ByteString) -> Maybe Packet
processPacket (header, content) = case SG.runGet (parseEthernetFrame >> parseIpFrame >> parseUDPFrame) content of
	((Right udp), _) -> let qp = parseQPacket $ udp_payload udp in
		if (q_dtype qp == "B6" && q_itype qp == "03" && q_mtype qp == "4")
			then Just $ Packet (parsePacketTime header) (parseQPacketTime $ q_accept qp) qp
			else Nothing
	_ -> Nothing

-- main

main9 = runFrame $ printerF <-< sortF (\x y -> y - x > 100) <-< (Frame $ close $ mapM_ yieldF [4, 9, 1, 2, 3])

sortFrame :: Monad m => Frame Packet Packet m r
sortFrame = sortF (\p1 p2 -> p_time p2 - p_qtime p1 > 3000)

-- processFrame :: Monad m => Frame () Packet m ()
processFrame = 
	mapF fromJust <-< filterF isJust <-<
	mapF processPacket <-<
	-- take' 100 <-<
	readPcapF "mdf-kospi200.20110216-0.pcap"
	-- readPcapF "merge3.pcap"

parseArgs ["-r"] = sortFrame <-< processFrame
parseArgs _ = processFrame

main = do
	args <- getArgs
	runFrame $ printerF <-< parseArgs args

-- Tests

toList :: (Monad m) => Frame a Void m [a]
toList = Frame go where
     go = do
         x <- await
         case x of
             Nothing -> close $ pure []
             Just a  -> fmap (fmap (a:)) go
             -- the extra fmap is an unfortunate extra detail

instance Arbitrary Packet where
	arbitrary = do
		p_time <- arbitrary
		p_qtime <- arbitrary
		return $ Packet p_time p_qtime (QPacket "" "" "" "" "" "" "" [] "" [] "")

prop_packet :: [Packet] -> Bool
prop_packet packets = let
	fpackets = sortBy (\x y -> compare (p_time x) (p_time y)) $ filter (\p -> p_time p - p_qtime p <= 3000) packets
	spackets = fromJust $ fromJust $ runFrame $
			(Just <$> toList) <-<
			sortFrame <-<
			(Nothing <$ (Frame $ close $ mapM_ yieldF fpackets))
		in sort fpackets == spackets

-- Analysis
--
-- COST CENTRE                    MODULE               %time %alloc

-- readNextF                      Main                  51.0    0.6
-- printerF                       Main                  21.8    8.7
-- parseQPacketTime               Main                  11.6   22.5
-- parseUDPFrame                  Main                   6.1   23.1
-- parsee                         Main                   4.8   26.8

-- Half the time is spent in readNextF. Since readNextF doesn't do anything special really but call into native code,
-- I'm assuming that this is incurred by libpcap itself.
-- IO seems to take another huge chunk of the total time; print is slow.
-- Interestingly, almost 12%, and sometimes up to 20% are spent in the rather uninteristing function parseQPacketTime
-- converting qpacket strings to a timestamp. Most of the time seems to be spent in the conversion of POSIXTime ->
-- Int, hacked together with floor. Unfortunately, I didn't find a faster way to do that using ordinary Haskell libs.
-- A potential optimization would be to just call into native C code.

-- Heap usage seems to be stable at around ~10k, with the occasional spikes up to 20, 25k. Those can be explained by
-- the fact that sortF has to maintain a running priority queue of all incoming packets until the packet time of the
-- most recent packet minus 3000ms is greater than the accept time of the least recent packet. If timestamps are
-- distributed densely, the queue can grow until the 3000ms interval is reached. After that, memory is gradually
-- GCd when fewer packets start spanning the difference interval.
