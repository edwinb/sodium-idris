module Crypto.Sodium

import Crypto.RawSodium

%access public

-- Key generation

abstract data Key = MkKey ManagedPtr

newKey : (len : Int) -> IO Key
newKey l = return $ MkKey !(do_newKey l)

newSymmKey : IO Key
newSymmKey = do len <- secretbox_keyLength
                newKey len

newSecretKey : IO Key
newSecretKey = do len <- box_secretKeyLength
                  newKey len

newPublicKey : IO Key
newPublicKey = do len <- box_publicKeyLength
                  newKey len

newKeyPair : IO (Key, Key)
newKeyPair = do kp <- do_newKeyPair
                pk <- do_getPublic kp
                sk <- do_getSecret kp
                do_freeKeyPair kp
                return (MkKey pk, MkKey sk)

keyLen : Key -> Int
keyLen (MkKey k) = unsafePerformIO (do_getKeyLen k)

keyIdx : Key -> Int -> Int
keyIdx (MkKey k) i = unsafePerformIO (do_getKeyIdx k i)

setKeyIdx : Key -> Int -> Int -> IO ()
setKeyIdx (MkKey k) i b = do_setKeyIdx k i b

-- freeKey : Key -> IO ()
-- freeKey (MkKey p) = do_freeKey p

-- An Encrypted box holds raw encrypted data, and its length
abstract 
data EncryptedBox = MkEnc ManagedPtr | EncFailed

newSymmBox : Int -> IO EncryptedBox
newSymmBox l = return $ MkEnc !(do_newSecretBox l)

newBox : Int -> IO EncryptedBox
newBox l = return $ MkEnc !(do_newBox l)

getBoxLen : EncryptedBox -> Int
getBoxLen (MkEnc e) = unsafePerformIO $ do_getBoxLen e

getBoxIdx : EncryptedBox -> Int -> Int
getBoxIdx (MkEnc e) i = unsafePerformIO $ do_getBoxIdx e i

getBytes : EncryptedBox -> List Int
getBytes e = getAll [] 0 (getBoxLen e) 
   where getAll : List Int -> Int -> Int -> List Int
         getAll acc i len
             = if i == len 
                  then reverse acc
                  else getAll (getBoxIdx e i :: acc) (i + 1) len

abstract validBox : EncryptedBox -> Bool
validBox (MkEnc e) = True
validBox EncFailed = False

-- freeBox : EncryptedBox -> IO ()
-- freeBox (MkEnc e) = do_freeBox e

-- An open box holds plain text, and its length
abstract data OpenBox = MkDec ManagedPtr | DecFailed

abstract readBox : OpenBox -> String
readBox (MkDec p) = unsafePerformIO (do_readBoxOpen p)

abstract validOpenBox : OpenBox -> Bool
validOpenBox (MkDec e) = True
validOpenBox DecFailed = False

-- freeOpenBox : OpenBox -> IO ()
-- freeOpenBox (MkDec e) = do_freeBoxOpen e

-- Nonce lengths

abstract symmNonceLength : Int
symmNonceLength = unsafePerformIO secretbox_nonceLength

abstract nonceLength : Int
nonceLength = unsafePerformIO box_nonceLength

-- Symmetric key encryption

cryptoSecretBox : (plaintext : String) -> (nonce : String) ->
                  (key : Key) -> IO EncryptedBox
cryptoSecretBox m n (MkKey k) 
    = case !(do_cryptoSecretBox m n k) of
           Just p => return (MkEnc p)
           Nothing => return EncFailed

cryptoSecretBoxOpen : (ciphertext : EncryptedBox) -> (nonce : String) ->
                      (key : Key) -> IO OpenBox
cryptoSecretBoxOpen (MkEnc e) n (MkKey k) 
    = case !(do_cryptoSecretBoxOpen e n k) of
           Just p => return (MkDec p)
           Nothing => return DecFailed

-- Public key encryption

cryptoBox : (plaintext : String) -> (nonce : String) ->
            (pkey : Key) -> (skey : Key) -> IO EncryptedBox
cryptoBox m n (MkKey pk) (MkKey sk)
    = case !(do_cryptoBox m n pk sk) of
           Just p => return (MkEnc p)
           Nothing => return EncFailed

cryptoBoxOpen : (ciphertext : EncryptedBox) -> (nonce : String) ->
                (pkey : Key) -> (skey : Key) -> IO OpenBox
cryptoBoxOpen (MkEnc e) n (MkKey pk) (MkKey sk)
    = case !(do_cryptoBoxOpen e n pk sk) of
           Just p => return (MkDec p)
           Nothing => return DecFailed


