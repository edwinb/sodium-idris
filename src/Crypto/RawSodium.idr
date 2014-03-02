module Crypto.RawSodium

%lib     C "sodium"
%link    C "sodium_glue.o"
%include C "sodium_glue.h"

-- RAW INTERFACE
-- Key and nonce lengths

box_nonceLength : IO Int
box_nonceLength = mkForeign (FFun "box_nonceLength" [] FInt)

box_secretKeyLength : IO Int
box_secretKeyLength = mkForeign (FFun "box_secretKeyLength" [] FInt)

box_publicKeyLength : IO Int
box_publicKeyLength = mkForeign (FFun "box_publicKeyLength" [] FInt)

secretbox_nonceLength : IO Int
secretbox_nonceLength = mkForeign (FFun "box_nonceLength" [] FInt)

secretbox_keyLength : IO Int
secretbox_keyLength = mkForeign (FFun "secretbox_keyLength" [] FInt)

-- Create/read/write keys

do_newKey : Int -> IO ManagedPtr
do_newKey len = do p <- mkForeign (FFun "mkKey" [FInt] FPtr) len 
                   return $ registerPtr p (len+16) 

do_getKeyLen : ManagedPtr -> IO Int
do_getKeyLen p = mkForeign (FFun "keyLen" [FManagedPtr] FInt) p

do_getKeyIdx : ManagedPtr -> Int -> IO Int
do_getKeyIdx p i = mkForeign (FFun "keyIdx" [FManagedPtr, FInt] FInt) p i

do_setKeyIdx : ManagedPtr -> Int -> Int -> IO ()
do_setKeyIdx p i b 
     = mkForeign (FFun "setKeyIdx" [FManagedPtr, FInt, FInt] FUnit) p i b

-- Create/read/write nonces

do_newNonce : Int -> IO ManagedPtr
do_newNonce len = do p <- mkForeign (FFun "mkNonce" [FInt] FPtr) len 
                     return $ registerPtr p (len+16) 

do_newNonceFromString : String -> IO ManagedPtr
do_newNonceFromString s
     = do p <- mkForeign (FFun "mkNonceFromString" [FString] FPtr) s
          return $ registerPtr p (cast (length s) + 16) 

do_setNonceIdx : ManagedPtr -> Int -> Int -> IO ()
do_setNonceIdx p i b 
     = mkForeign (FFun "setNonceIdx" [FManagedPtr, FInt, FInt] FUnit) p i b

-- Making/reading boxes

do_newBox : Int -> IO ManagedPtr
do_newBox len = do p <- mkForeign (FFun "newBox" [FInt] FPtr) len 
                   return $ registerPtr p (len + 16)

do_newSecretBox : Int -> IO ManagedPtr
do_newSecretBox len = do p <- mkForeign (FFun "newBox" [FInt] FPtr) len 
                         return $ registerPtr p (len + 16)

do_getBoxLen : ManagedPtr -> IO Int
do_getBoxLen p = mkForeign (FFun "getEncLen" [FManagedPtr] FInt) p

do_getBoxIdx : ManagedPtr -> Int -> IO Int
do_getBoxIdx p i = mkForeign (FFun "getEncByte" [FManagedPtr, FInt] FInt) p i

do_setBoxIdx : ManagedPtr -> Int -> Int -> IO ()
do_setBoxIdx p i b 
     = mkForeign (FFun "setEncByte" [FManagedPtr, FInt, FInt] FUnit) p i b

-- Reading results of operations (symmetric or public key)

do_readBoxOpen : ManagedPtr -> IO String
do_readBoxOpen p = mkForeign (FFun "getDec" [FManagedPtr] FString) p

-- Symmetric keys

do_cryptoSecretBox : (msg : String) -> 
                     (nonce : ManagedPtr) -> 
                     (key : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoSecretBox m n k 
   = do p <- mkForeign (FFun "do_crypto_secretbox" 
                       [FString, FManagedPtr, FManagedPtr] FPtr) m n k
        if !(nullPtr p) 
           then return Nothing
           else do boxlen <- mkForeign (FFun "getEncSize" [FPtr] FInt) p
                   return $ Just (registerPtr p (boxlen + 16))


do_cryptoSecretBoxOpen : (ciphertext : ManagedPtr) -> 
                         (nonce : ManagedPtr) -> 
                         (key : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoSecretBoxOpen c n k 
   = do p <- mkForeign (FFun "do_crypto_secretbox_open" 
                       [FManagedPtr, FManagedPtr, FManagedPtr] FPtr) c n k
        if !(nullPtr p)
           then return Nothing
           else do boxlen <- mkForeign (FFun "getDecSize" [FPtr] FInt) p
                   return $ Just (registerPtr p (boxlen + 16))

-- Public keys

do_newKeyPair : IO Ptr
do_newKeyPair = mkForeign (FFun "newKeyPair" [] FPtr)

do_getPublic : Ptr -> IO ManagedPtr
do_getPublic kp = do p <- mkForeign (FFun "getPublic" [FPtr] FPtr) kp
                     len <- mkForeign (FFun "keyLen" [FPtr] FInt) p
                     return $ registerPtr p (len + 16)

do_getSecret : Ptr -> IO ManagedPtr
do_getSecret kp = do p <- mkForeign (FFun "getSecret" [FPtr] FPtr) kp
                     len <- mkForeign (FFun "keyLen" [FPtr] FInt) p
                     return $ registerPtr p (len + 16)

do_cryptoBox : (msg : String) -> 
               (nonce : ManagedPtr) -> 
               (pkey : ManagedPtr) -> 
               (skey : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoBox m n pk sk
   = do p <- mkForeign (FFun "do_crypto_box" 
                       [FString, FManagedPtr, FManagedPtr, FManagedPtr] FPtr) m n pk sk
        if !(nullPtr p)
           then return Nothing
           else do boxlen <- mkForeign (FFun "getEncSize" [FPtr] FInt) p
                   return $ Just (registerPtr p (boxlen + 16))

do_cryptoBoxOpen : (ciphertext : ManagedPtr) -> 
                   (nonce : ManagedPtr) -> 
                   (pkey : ManagedPtr) -> 
                   (skey : ManagedPtr) -> IO (Maybe ManagedPtr)
do_cryptoBoxOpen c n pk sk 
   = do p <- mkForeign (FFun "do_crypto_box_open" 
                       [FManagedPtr, FManagedPtr, FManagedPtr, FManagedPtr] FPtr) c n pk sk
        if !(nullPtr p)
           then return Nothing
           else do boxlen <- mkForeign (FFun "getDecSize" [FPtr] FInt) p
                   return $ Just (registerPtr p (boxlen + 16))

-- Releasing memory for keys and results of encryption/decryption

-- do_freeBox : Ptr -> IO ()
-- do_freeBox p = mkForeign (FFun "freeEnc" [FPtr] FUnit) p
-- 
-- do_freeBoxOpen : Ptr -> IO ()
-- do_freeBoxOpen p = mkForeign (FFun "freeDec" [FPtr] FUnit) p
-- 
-- do_freeKey : Ptr -> IO ()
-- do_freeKey p = mkForeign (FFun "freeKey" [FPtr] FUnit) p

do_freeKeyPair : Ptr -> IO ()
do_freeKeyPair p = mkForeign (FFun "freeKeyPair" [FPtr] FUnit) p


