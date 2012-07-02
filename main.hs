import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Internal as B

import Debug.Trace

import Data.Time.Format
import Data.Time.LocalTime
import Data.Time.Clock
import Data.Time.Clock.POSIX

import System.Locale

import Control.Applicative

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

readFileP :: FilePath -> Producer String IO ()
readFileP name = do
	contents <- lift $ readFile name
	let lns = lines contents
	mapM_ yield lns

readFileF :: FilePath -> Frame () String IO ()
readFileF name = Frame $ close $ do
	contents <- lift $ readFile name
	let lns = lines contents
	mapM_ yieldF lns

lineLengthP :: (Monad m) => Pipe String Int m ()
lineLengthP = forever $ await >>= yield . length

printer :: (Show a) => Consumer a IO b
printer = forever $ do
	x <- await
	lift $ print x

printerF :: (Show a) => Frame a Void IO r
printerF = Frame $ forever $ do
	x <- awaitF
	lift $ print x

readPcap :: FilePath -> IO ()
readPcap name = do
	h <- PC.openOffline name
	(header, bs) <- PC.nextBS h
	print $ PC.hdrTime header

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
 
main2 = runFrame $ printerF <-< readFileF "main.hs"

toBS :: (PktHdr, Ptr Word8) -> IO (PktHdr, B.ByteString)
toBS (hdr, ptr) = do
    let len = hdrCaptureLength hdr
    s <- B.create (fromIntegral len) $ \p -> B.memcpy p ptr (fromIntegral len)
    return (hdr, s)

take' :: Int -> Frame a a IO ()
take' n
   | n < 1 = Frame $ close $ lift $ putStrLn "You shall not pass!"
   | otherwise = Frame $ do
         replicateM_ (n - 1) $ do
             x <- awaitF
             yieldF x
         x <- awaitF
         close $ do
             lift $ putStrLn "You shall not pass!"
             yieldF x

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
	lift $ print "openging file"
	h <- lift $ openPcap name
	finallyP (closePcap h >> print "closing file") (readNextF h)

mapF :: (Monad m) => (a -> b) -> Frame a b m r
mapF f = Frame $ forever $ do
	x <- awaitF
	yieldF $ f x

printHdr :: (PktHdr, BS.ByteString) -> Word32
printHdr (hdr, _) = hdrUseconds hdr

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

newtype Bid = Bid (String, String) deriving Show
newtype Ask = Ask (String, String) deriving Show

data QPacket = QPacket {q_dtype :: String, q_itype :: String, q_mtype :: String, q_icode :: String,
	q_isno :: String, q_mstype :: String, q_tbid :: String, q_bids :: [Bid], q_task :: String, q_asks :: [Ask], q_accept :: String} deriving Show

tstr = map (toEnum . fromEnum)

parsee :: [Int] -> [Word8] -> [[Word8]]
parsee intervals bytes = fst $ foldl (\(list, bytes) x -> let (w, bytes') = splitAt x bytes in (list ++ [w], bytes')) ([], bytes) intervals

parseBid :: [Word8] -> Bid
parseBid bytes = let [price, quant] = map tstr $ parsee [5, 7] bytes in
	Bid (price, quant)

parseAsk :: [Word8] -> Ask
parseAsk bytes = let [price, quant] = map tstr $ parsee [5, 7] bytes in
	Ask (price, quant)

parseQPacket :: [Word8] -> QPacket
parseQPacket bytes = let
	parseMany n f b = map f $ parsee (replicate n 12) b
	parsed@[_, _, _, _, _, _, _, bids, _, asks, _, _] = parsee [2, 2, 1, 12, 3, 2, 7, 60, 7, 60, 50, 8] bytes
	[q_dtype, q_itype, q_mtype, q_icode, q_isno, q_mstype, q_tbid, _, q_task, _, _, q_accept] = map tstr parsed in
		QPacket q_dtype q_itype q_mtype q_icode q_isno q_mstype q_tbid (parseMany 5 parseBid bids) q_task (parseMany 5 parseAsk asks) q_accept

-- Sort

sortAccumF :: Monad m => Ord a => (a -> a -> Bool) -> [a] -> Ensure a a m ()
sortAccumF f a@(x:xs) = do
	n <- await
	case n of
		Nothing -> mapM_ yieldF a
		Just n' -> if f x n'
			then do
				yieldF x
				sortAccumF f $ insert n' xs
			else
				sortAccumF f $ insert n' a
sortAccumF f [] = do
	n <- awaitF
	sortAccumF f [n]

sortF :: Monad m => Ord a => (a -> a -> Bool) -> Frame a a m r
sortF f = Frame $ forever $ sortAccumF f []

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
		q_icode qp

instance Eq Packet where
	(==) p1 p2 = p_qtime p1 == p_qtime p2

instance Ord Packet where
	compare p1 p2 = compare (p_qtime p1) (p_qtime p2)

processPacket :: (PktHdr, BS.ByteString) -> Maybe Packet
processPacket (header, content) = let
	((Right udp), _) = SG.runGet (parseEthernetFrame >> parseIpFrame >> parseUDPFrame) content
	qp = parseQPacket $ udp_payload udp in
		if (q_dtype qp == "B6" && q_itype qp == "03" && q_mtype qp == "4")
			then Just $ Packet (parsePacketTime header) (parseQPacketTime $ q_accept qp) qp
			else Nothing

-- main

main9 = runFrame $ printerF <-< sortF (\x y -> y - x > 100) <-< (Frame $ close $ mapM_ yieldF [4, 9, 1, 2, 3])

main = runFrame $
	printerF <-<
	sortF (\p1 p2 -> p_time p2 - p_qtime p1 > 3000) <-<
	mapF fromJust <-< filterF isJust <-<
	mapF processPacket <-<
	take' 10 <-<
	readPcapF "mdf-kospi200.20110216-0.pcap"

