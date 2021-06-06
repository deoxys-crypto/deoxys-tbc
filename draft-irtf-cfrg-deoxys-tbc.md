---
title: "Deoxys Tweakable Block Ciphers" 
abbrev: "Deoxys-TBC" 
docname: draft-irtf-cfrg-deoxys-tbc-latest 
category: info 

ipr: trust200902 
area: General 
workgroup: Crypto Forum 
keyword: Internet-Draft, Deoxys, tweakable block cipher 

stand_alone: yes
coding: UTF-8
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: T. Peyrin
    name: Thomas Peyrin
    organization: Nanyang Technological University, Singapore
    email: thomas.peyrin@gmail.com
    
 -
    ins: C. Guo
    name: Chun Guo
    organization: School of Cyber Science and Technology, Shandong University, China
    email: chun.guo.sc@gmail.com

normative:
  RFC2119:

informative:
  ABF13:
    target: https://eprint.iacr.org/2015/204.pdf
    title: "Leakage-Resilient Symmetric Encryption via Re-keying"
    author: 
      -
        name: Michel Abdalla
      -  
        name: Sonia Belaïd
      -  
        name: Pierre-Alain Fouque
    seriesinfo: "Proceedings of the 15th International Workshop Cryptographic Hardware and Embedded Systems – CHES 2013, Lecture Notes in Computer Science 8086, pp.471-488"
    date: 2013
    PDF: https://eprint.iacr.org/2015/204.pdf
  
  
  BGPPS19:
    target: https://eprint.iacr.org/2019/137.pdf
    title: "TEDT, a Leakage-Resilient AEAD mode for High Physical Security Applications"
    author: 
      -
        name: Francesco Berti
      -  
        name: Chun Guo
      -  
        name: Olivier Pereira
      -  
        name: Thomas Peters
      -  
        name: François-Xavier Standaert
    seriesinfo: "IACR Trans. Cryptogr. Hardw. Embed. Syst."
    date: 2020
    PDF: https://eprint.iacr.org/2019/137.pdf
    
    
  BT16:
    target: https://eprint.iacr.org/2016/564.pdf
    title: "The Multi-User Security of Authenticated Encryption: AES-GCM in TLS 1.3"
    author: 
      -
        name: Mihir Bellare
      -  
        name: Bjorn Tackmann
    seriesinfo: "Proceedings of the 36th Annual International Cryptology Conference – CRYPTO 2016, Lecture Notes in Computer Science 9814, pp.247-276"
    date: 2020
    PDF: https://eprint.iacr.org/2016/564.pdf


  FIPS-197:
    target: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    title: "Advanced Encryption Standard (AES)"
    author: 
        org: National Institute of Standards and Technology
      
    seriesinfo: "FIPS PUB 197"
    date: 2001
    PDF: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

  
  BGPPS19:
    target: https://eprint.iacr.org/2019/137.pdf
    title: "TEDT, a Leakage-Resilient AEAD mode for High Physical Security Applications"
    author: 
      -
        name: Francesco Berti
      -  
        name: Chun Guo
      -  
        name: Olivier Pereira
      -  
        name: Thomas Peters
      -  
        name: François-Xavier Standaert
    seriesinfo: "IACR Trans. Cryptogr. Hardw. Embed. Syst."
    date: 2020
    PDF: https://eprint.iacr.org/2019/137.pdf


  GIKMP21:
    target: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
    title: "Romulus v1.3"
    author: 
      -
        name: Chun Guo
      -  
        name: Tetsu Iwata
      -  
        name: Mustafa Khairallah
      -
        name: Kazuhiko Minematsu
      -
        name: Thomas Peyrin
    seriesinfo: "Submission of finalists of the lightweight crypto standardization process"
    date: 2021
    PDF: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf


  JNPS14:
    target: https://competitions.cr.yp.to/round3/deoxysv14.pdf
    title: "Tweaks and Keys for Block Ciphers: the TWEAKEY Framework"
    author: 
      -
        name: J. Jean 
      -  
        name: I. Nikolić
      -  
        name: T. Peyrin
      -  
        name: Y. Seurin
    seriesinfo: "CAESAR: Competition for Authenticated Encryption: Security, Applicability, and Robustness"
    date: 2014
    PDF: https://competitions.cr.yp.to/round3/deoxysv14.pdf


--- abstract

This document defines the Deoxys-TBC tweakable block ciphers, which comes in two versions Deoxys-TBC-256 (256 bits of key and tweak material) and Deoxys-TBC-384 (384 bits of key and tweak material). They are based on the Advanced Encryption Standard round function to benefit from previous security analysis and deployed hardware acceleration. 

This document builds up on the definitions of the Advanced Encryption Standard in \[[FIPS-197](FIPS-197)\], and is meant to serve as a stable reference and an implementation guide.

--- middle

# Introduction

A tweakable block cipher (TBC) is a family of permutations parametrised by a secret key K and a public tweak value T. This document defines the Deoxys-TBC tweakable block ciphers: Deoxys-TBC-256 (providing 256 bits of key and tweak material) and Deoxys-TBC-384 (providing 384 bits of key and tweak material), both having a block size of 128 bits. 

They are based on the round function of the Advanced Encryption Standard (AES) block cipher and are actually very similar to AES: they can be viewed as a tweakable version of AES, where the key schedule has been updated and more rounds are used to properly handle the extra tweak input. The similarity with AES allows to benefit from the extensive security analysis already provided on the worldwide block encryption standard. Moreover, the reuse of the AES round function leverages the growing deployement of AES hardware acceleration. 

Tweakable block ciphers are very versatile and useful primitives that can be placed in specially crafted operating modes to provide advanced security features that would be harder to obtain with classical block ciphers. For example, a classical shortcomming of most block cipher-based operating modes is that they can only reach birthday-bound security 2^(n/2) with respect to the block length n of the underlying primitive. In the case of AES with a 128-bit block size, this means that security is lost at 2^64 block cipher calls at best, which is low given modern security requirements (for 64-bit block ciphers, the situation would be even more problematic). In contrary, tweakable block ciphers can easily and efficiently build so-called beyond birthday-bound schemes, that guarantee a high security even for 2^(n/2) data and beyond. 

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

The following notations are used throughout the document:

* n: plaintext/ciphertext bit-length of the tweakable block cipher. In the case of Deoxys-TBC, we have n=128.
* k: key bit-length of the tweakable block cipher. In the case of Deoxys-TBC, we have 128 ≤ k ≤ 256.
* t: tweak bit-length of the tweakable block cipher.
* Nr: the number of rounds of the tweakable block cipher. In the case of Deoxys-TBC-256 we have Nr=14, while for Deoxys-TBC-384 we have Nr=16.
* X\|\|Y: concatenation of bit strings X and Y.
* \|X\|: bit length of a string X.
* \|\|X\|\|: byte length of a string X.
* epsilon: empty string.
* trunc\_i(X): truncation of the bitstring X to the least significant i bits.
* a ← b: replace the value of the variable a with the value of the variable b.
* XOR: bitwise exclusive-OR operation.
* \[i, ... , j\]: sequence of integers starting from i included, ending at j included, with a step of 1.
* (i)\_b: the encoding of the integer i on b bits.
* TBC_K\[T\](P): encryption with a tweakable block cipher of plaintext P with tweak T and key K.
* TBC-1_K\[T\](C): decryption with a tweakable block cipher of ciphertext C with tweak T and key K.
* TBC\[TK\](P): encryption with a tweakable block cipher of plaintext P with tweakey TK.
* TBC-1\[TK\](C): decryption with a tweakable block cipher of ciphertext C with tweakey TK.
* ozpad\_i(X): padding of the bitstring X (with 0<\|X\|≤i), such that ozpad\_i(X) = X if \|X\|=i, ozpad\_i(X) = X \|\| (1)\_1 \|\| (0)\_(i-\|X\|-1) otherwise.
* ipad\_i(X): padding of the byte string X, such that ipad\_i(X) = X \|\| (0)\_(i-(\|X\| mod i)-8) \|\| ( (\|X\| mod i) / 8 )\_8.
* ipad\*\_i(X): padding of the byte string X, such that ipad\*\_i(X) = X \|\| (0)\_(i-(\|X\| mod i)-8) \|\| ( (\|X\| mod i) / 8 )\_8 if \|X\| != epsilon, ipad\*\_i(X) = epsilon otherwise (i.e., X = epsilon).


# The Deoxys-TBC Tweakable Block Ciphers

We describe here the Deoxys-TBC tweakable block ciphers, as published in \[[JNP14](JNP14)\] and \[[JNPS14](JNPS14)\]. Deoxys-TBC-256 and Deoxys-TBC-384 propose a so-called tweakey input that can be utilized as key and/or tweak material, up to the user needs. Therefore, the user can freely choose which part of the tweakey is dedicated to key and/or tweak material. However, whatever combination of key/tweak size chosen by the user, it SHALL be such that the key size is at least 128 bits and at most 256 bits (if different tweak/key configurations or placements are to be allowed, proper separation of these versions are to be ensured at protocol level in order to avoid trivial related-cipher attacks). This document describes the default configuration where the tweakey input is loaded with the tweak first (least significant portion of the tweakey), and the key material after (most significant portion of the tweakey), i.e. tweakey = key \|\| tweak. Therefore, TBC_K\[T\](P) will denote the application of the Deoxys-TBC with tweakey = K \|\| T.

Deoxys-TBC operate on blocks of 128 bits seen as a (4×4) matrix of bytes which are numbered

~~~~ 
[ 0  4  8 12 ]
[ 1  5  9 13 ]
[ 2  6 10 14 ]
[ 3  7 11 15 ]
~~~~ 

and a tweakey length of size 256 bits (for Deoxys-TBC-256) or 384 bits (for Deoxys-TBC-384). For Deoxys-TBC-256 the tweakey consists of a key of size k ≥ 128 and a tweak of size t = 256-k. For Deoxys-TBC-384 the tweakey consists of a key of size k ≥ 128 and a tweak of size t = 384-k. 

## Deoxys-TBC encryption

Let the composition MixBytes(ShiftRows(SubBytes(X))) represent an unkeyed AES round on a state X and we denote it AES_R(X), see \[[FIPS-197](FIPS-197)\]. The encryption with Deoxys-TBC of a 128-bit plaintext P gives a 128-bit ciphertext C that is defined as:  

~~~~ 
X[0] ← P
X[i+1] ← AES_R(AddSTK(X[i] , STK[i])) for i in [0, ... , Nr-1]
C ← AddSTK(X[Nr] , STK[Nr])
~~~~ 

where AddSTK(X, STK) is the operating consisting of XORing the 128-bit round sub-tweakey STK (defined further) to the internal state X (AddSTK stands for AddSubTweakey). The number of rounds Nr is 14 for Deoxys-TBC-256 and 16 for Deoxys-TBC-384.  

## Deoxys-TBC decryption

Let the composition SubBytesInv(ShiftRowsInv(MixBytesInv(X))) represent an unkeyed AES inverse round on a state X and we denote it AES_R-1(X), see \[[FIPS-197](FIPS-197)\]. The decryption with Deoxys-TBC of a 128-bit ciphertext C gives a 128-bit plaintext P that is defined as:  

~~~~ 
X[0] ← C
X[i+1] ← AES_R-1(AddSTK(X[i] , STK[Nr-i])) for i in [0, ... , Nr-1]
P ← AddSTK(X[Nr] , STK[0])
~~~~ 

## Deoxys-TBC tweakey schedule

We denote TK the input tweakey state and we divide it into words of 128 bits. More precisely, in Deoxys-TBC-256, the size of TK is 256 bits with the first (most significant) 128 bits of TK being denoted W2, while the second W1. For Deoxys-TBC-384, the size of TK is 384 bits, with the first (most significant) 128 bits of TK being denoted W3, the second W2 and the third W1. Finally, we denote with STK\[i\] the sub-tweakey (a 128-bit word) that is added to the state at round i of the cipher during the AddSTK operation. For Deoxys-TBC-256, a sub-tweakey for round i is defined as: 

~~~~ 
STK[i] = TK1[i] XOR TK2[i] XOR RC[i]  
~~~~ 

whereas for the case of Deoxys-TBC-384 it is defined as:

~~~~ 
STK[i] = TK1[i] XOR TK2[i] XOR TK3[i] XOR RC[i]  
~~~~ 

The 128-bit words TK1\[i\], TK2\[i\], TK3\[i\] are outputs produced by a tweakey schedule algorithm, initialized with TK1\[0\]=W1 and TK2\[0\]=W2 for Deoxys-TBC-256 (TK3\[i\] is ignored for Deoxys-TBC-256) and with TK1\[0\]=W1, TK2\[0\]=W2 and TK3\[0\]=W3 for Deoxys-TBC-384. The tweakey schedule algorithm uses two Linear-Feedback Shift Registers (LFSR) and is defined as:

~~~~  
TK1[i+1] = h(TK1[i]),  
TK2[i+1] = LFSR2(h(TK2[i])),  
TK3[i+1] = LFSR3(h(TK3[i])) in the case of Deoxys-TBC-384 
~~~~ 

where the byte permutation h is defined as:  

~~~~ 
[ 0  4  8 12 ]        [ 1  5  9 13 ]
[ 1  5  9 13 ]        [ 6 10 14  2 ]
[ 2  6 10 14 ]  --->  [11 15  3  7 ]
[ 3  7 11 15 ]        [12  0  4  8 ]
~~~~ 

The LFSR2 and LFSR3 functions are the application of an LFSR to each of the 16 bytes of a tweakey 128-bit word. More precisely, the two LFSRs used are given below (x0 stands for the LSB of the cell and x7 for the MSB):

~~~~ 
LFSR2: 
(x7||x6||x5||x4||x3||x2||x1||x0) 
--> (x6||x5||x4||x3||x2||x1||x0||x7 XOR x5)

LFSR3: 
(x7||x6||x5||x4||x3||x2||x1||x0)
--> (x0 XOR x6||x7||x6||x5||x4||x3||x2||x1)
~~~~ 

Finally, RC\[i\] are the key schedule round constants, and are defined as:

~~~~ 
        [ 1  RCON[i]  0  0 ]
        [ 2  RCON[i]  0  0 ]
RC[i] = [ 4  RCON[i]  0  0 ]
        [ 8  RCON[i]  0  0 ] 
~~~~ 

where RCON\[i\] denotes the (i+15)-th key schedule constants of the AES. These constants are also given in hexadecimal notation below: 

~~~~ 
i        | 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  |   
RCON[i]  | 2f | 5e | bc | 63 | c6 | 97 | 35 | 6a |  

i        | 8  | 9  | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
RCON[i]  | d4 | b3 | 7d | fa | ef | c5 | 91 | 39 | 72 |
~~~~ 


## Deoxys-TBC pseudocode

We provide below pseudocode for both versions of Deoxys-TBC. Note that in the tweakey schedule function, instead of applying the h byte permutation to each TKi word at every iteration, one can simply apply h, h^2, h^3, etc. after the XOR of the TKi words (i.e. for j>0 we have STK\[j\] = h^j(TK1 XOR TK2) XOR RC\[j\] for Deoxys-TBC-256 or STK\[j\] = h^j(TK1 XOR TK2 XOR TK3) XOR RC\[j\] for Deoxys-TBC-384). 

### Deoxys-TBC-256

~~~~
tweakey_schedule_256(tweakey):
    (TK2,TK1) <- tweakey
    STK[0] = TK1 ^ TK2 ^ RC[0]
    for j = 1 upto 14
       TK1 = h(TK1)
       TK2 = LFSR2(h(TK2))
       STK[j] = TK1 ^ TK2 ^ RC[j]
       end
    end

deoxys_tbc_256_encrypt(tweakey, plaintext):
    STK = tweakey_schedule_256(tweakey)
    block = plaintext
    for j = 0 upto 13
       block ^= STK[j]
       block = AES_ROUND(block)
       end
    return block ^ STK[14]   
    end

deoxys_tbc_256_decrypt(tweakey, ciphertext):  
    STK = tweakey_schedule_256(tweakey)
    block = ciphertext ^ STK[14] 
    for j = 13 downto 0       
       block = AES_ROUND_INVERSE(block)
       block ^= STK[j]
       end
    return block   
    end
~~~~


### Deoxys-TBC-384

~~~~
tweakey_schedule_384(tweakey):
    (TK3,TK2,TK1) <- tweakey
    STK[0] = TK1 ^ TK2 ^ TK3 ^ RC[0]
    for j = 1 upto 16
       TK1 = h(TK1)
       TK2 = LFSR2(h(TK2))
       TK3 = LFSR3(h(TK3))
       STK[j] = TK1 ^ TK2 ^ TK3 ^ RC[j]
       end
    end

deoxys_tbc_384_encrypt(tweakey, plaintext):
    STK = tweakey_schedule_384(tweakey)
    block = plaintext
    for j = 0 upto 15
       block ^= STK[j]
       block = AES_ROUND(block)
       end
    return block ^ STK[16]   
    end

deoxys_tbc_384_decrypt(tweakey, ciphertext):
    STK = tweakey_schedule_384(tweakey)
    block = ciphertext ^ STK[16] 
    for j = 15 downto 0
       block = AES_ROUND_INVERSE(block)
       block ^= STK[j]       
       end
    return block  
    end
           
~~~~

## Deoxys-TBC test vectors

We provide below test vectors for both versions of Deoxys-TBC, in hexadecimal display.

### Deoxys-TBC-256

~~~~ 
Tweakey:     Key:   101112131415161718191a1b1c1d1e1f   
             Tweak: 02021222324252627000000000000000

Plaintext:   1857d4edf080e8e2c83aa9e794ebf90d

Ciphertext:  f86ecad0d69d2c573cdeee96c90f37ac
~~~~ 


### Deoxys-TBC-384

~~~~ 
Tweakey:     Key:   101112131415161718191a1b1c1d1e1f 
             Tweak: 202122232425262728292a2b2c2d2e2f 
                    00001020304050607000000000000000

Plaintext:   d18db1b44ad16fe5623ccd73c250c272

Ciphertext:  e94c5c6df7c19474bbdd292baa2555fd
~~~~ 


# The Deoxys-AE1 AEAD Operating Mode

This single-pass nonce-based AEAD mode is an adaptation of the Deoxys-I AEAD operating mode from \[[JNPS14](JNPS14)\], the only difference being that Deoxys-TBC-384 is used internally instead of Deoxys-TBC-256, in order to handle more data per TBC call during the authentication, allowing longer nonce and larger maximum data size. 

This mode takes a secret key K of 128 bits, a nonce N of 128 bits and can handle associated data A and message M inputs of size up to 2^127 bits. It generates the corresponding ciphertext C and a tag of size tau≤128.


## Deoxys-AE1 encryption

The mode is divided into two independant parts: one part handling the authentication of the associated data and one part handling the authentication and encryption of the message blocks. The mode is created in such a way that all TBC calls will use a different tweak.

~~~
deoxys_AE1_encrypt(K, N, A, M):
  # Associated Data
  A[1] || ... || A[a] || A* <- A with |A[i]|=256 and |A*|<256

  Auth = 0
  for i = 0 upto a-1
     A_L || A_R <- A[i+1] with |A_L|=|A_R|=128
     Auth ^= TBC_K[(2)_8||(i)_120||A_L](A_R)       
     end

  #if padded block
  if |A*| != 0 then 
     A_L || A_R <- ozpad_256(A*) with |A_L|=|A_R|=128
     Auth ^= TBC_K[(6)_8||(a)_120||A_L](A_R)
     end

  # Message
  M[1] || ... || M[m] || M* <- M with |M[i]|=128 and |M*|<128

  Csum = 0
  for i = 0 upto m-1
     Csum ^= M[i+1]
     C[i+1] = TBC_K[(0)_8||(i)_120||N](M[i+1])       
     end

  #if padded block
  if |M*| == 0 then 
     Final = TBC_K[(1)_8||(m)_120||N](Csum)
     C* = epsilon
  else
     Csum ^= ozpad_128(M*)
     Pad = TBC_K[(4)_8||(m)_120||N]((0)_128)
     C* = M* ^ trunc_|M*|(Pad)
     Final = TBC_K[(5)_8||(m+1)_120||N](Csum)
     end

  # Tag Generation
  tag = Final ^ Auth
  return (C[1] || ... || C[m] || C* , tag)
~~~


## Deoxys-AE1 decryption

~~~
deoxys_AE1_decrypt(K, N, A, C, tag):
  # Associated Data
  A[1] || ... || A[a] || A* <- A with |A[i]|=256 and |A*|<256

  Auth = 0
  for i = 0 upto a-1
     A_L || A_R <- A[i+1] with |A_L|=|A_R|=128
     Auth ^= TBC_K[(2)_8||(i)_120||A_L](A_R)       
     end

  #if padded block
  if |A*| != 0 then 
     A_L || A_R <- ozpad_256(A*) with |A_L|=|A_R|=128
     Auth ^= TBC_K[(6)_8||(a)_120||A_L](A_R)
     end

  # Ciphertext
  C[1] || ... || C[m] || C* <- C with |C[i]|=128 and |C*|<128

  Csum = 0
  for i = 0 upto m-1
     M[i+1] = TBC-1_K[(0)_8||(i)_120||N](C[i+1])
     Csum ^= M[i+1]       
     end

  #if padded block
  if |C*| == 0 then 
     Final = TBC_K[(1)_8||(m)_120||N](Csum)
     M* = epsilon
  else     
     Pad = TBC_K[(4)_8||(m)_120||N]((0)_128)
     M* = C* ^ trunc_|C*|(Pad)
     Csum ^= ozpad_128(M*)
     Final = TBC_K[(5)_8||(m+1)_120||N](Csum)
     end

  # Tag Verification
  tag' = Final ^ Auth
  if tag' == tag then 
     return (M[1] || ... || M[m] || M*)
  else 
     return invalid
     end
~~~

## Deoxys-AE1 test vectors

TODO


# The Deoxys-AE2 AEAD Operating Mode

This two-pass nonce-based AEAD mode is an adaptation of the Deoxys-II AEAD operating mode from \[[JNPS14](JNPS14)\], the only difference being that Deoxys-TBC-384 is used internally instead of Deoxys-TBC-256, in order to handle more data per TBC call during the authentication, while getting better security bounds.  

This mode takes a secret key K of 128 bits, a nonce N of 128 bits and can handle associated data A and message M inputs of size up to 2^127 bits. It generates the corresponding ciphertext C and a tag of size tau<=128.

Note that the decryption is actually one-pass.


## Deoxys-AE2 encryption

~~~
deoxys_AE2_encrypt(K, N, A, M):
  # Associated Data
  A[1] || ... || A[a] || A* <- A with |A[i]|=256 and |A*|<256

  Auth = 0
  for i = 0 upto a-1
     A_L || A_R <- A[i+1] with |A_L|=|A_R|=128
     Auth ^= TBC_K[(2)_8||(i)_120||A_L](A_R)       
     end

  #if padded block
  if |A*| != 0 then 
     A_L || A_R <- ozpad_256(A*) with |A_L|=|A_R|=128
     Auth ^= TBC_K[(6)_8||(a)_120||A_L](A_R)
     end

  # Message Authentication
  M[1] || ... || M[m] || M* <- M with |M[i]|=256 and |M*|<256

  for i = 0 upto m-1
     M_L || M_R <- M[i+1] with |M_L|=|M_R|=128
     Auth ^= TBC_K[(0)_8||(i)_120||M_L](M_R)       
     end

  #if padded block
  if |M*| != 0 then 
     M_L || M_R <- ozpad_256(M*) with |M_L|=|M_R|=128
     Auth ^= TBC_K[(4)_8||(m)_120||M_L](M_R)
     end

  # Tag Generation
  tag = TBC_K[(1)_8||(0)_120||N](Auth)

  # Message Encryption
  M[1] || ... || M[m'] || M* <- M with |M[i]|=128 and |M*|<128

  for i = 0 upto m'-1    
     C[i+1] = M[i+1] ^ TBC_K[(3)_8||(i)_120||tag](N)       
     end

  #if padded block
  if |M*| != 0 then      
     C* = M* ^ trunc_|M*|(TBC_K[(7)_8||(m')_120||tag](N))
     end

  return (C[1] || ... || C[m'] || C* , tag)
~~~


## Deoxys-AE2 decryption

~~~
deoxys_AE2_decrypt(K, N, A, C, tag):
  # Message Decryption
  C[1] || ... || C[m'] || C* <- C with |C[i]|=128 and |C*|<128

  for i = 0 upto m'-1
     M[i+1] = C[i+1] ^ TBC_K[(3)_8||(i)_120||tag](N)          
     end

  #if padded block
  if |C*| != 0 then      
     M* = C* ^ trunc_|C*|(TBC_K[(7)_8||(m')_120||tag](N))
     end

  # Associated Data
  A[1] || ... || A[a] || A* <- A with |A[i]|=256 and |A*|<256

  Auth = 0
  for i = 0 upto a-1
     A_L || A_R <- A[i+1] with |A_L|=|A_R|=128
     Auth ^= TBC_K[(2)_8||(i)_120||A_L](A_R)       
     end

  #if padded block
  if |A*| != 0 then 
     A_L || A_R <- ozpad_256(A*) with |A_L|=|A_R|=128
     Auth ^= TBC_K[(6)_8||(a)_120||A_L](A_R)
     end

  # Message Authentication
  M <- M[1] || ... || M[m'] || M* 
  M[1] || ... || M[m] || M* <- M with |M[i]|=256 and |M*|<256

  for i = 0 upto m-1
     M_L || M_R <- M[i+1] with |M_L|=|M_R|=128
     Auth ^= TBC_K[(0)_8||(i)_120||M_L](M_R)       
     end

  #if padded block
  if |M*| != 0 then 
     M_L || M_R <- ozpad_256(M*) with |M_L|=|M_R|=128
     Auth ^= TBC_K[(4)_8||(m)_120||M_L](M_R)
     end

  # Tag Verification
  tag' = TBC_K[(1)_8||(0)_120||N](Auth)
  if tag' == tag then 
     return M
  else 
     return invalid
     end
~~~


## Deoxys-AE2 test vectors

TODO


# The Deoxys-AE3 AEAD Operating Mode

This mode is an adaptation of the Romulus-T AEAD scheme from \[[GIKMP21](GIKMP21)\] (which is further built upon the TEDT AEAD operating mode from \[[BGPPS19](BGPPS19)\]), the only difference being that Deoxys-TBC-384 is used instead of Skinny-128-384+ (in Romulus-T). Compared with the original TEDT \[[BGPPS19](BGPPS19)\], both Deoxys-AE3 and Romulus-T handle more data per TBC call during the authentication and allow longer nonce and larger maximum data size.  

This mode takes a secret key K of 128 bits, a nonce N of 128 bits and can handle associated data A and message M inputs of size up to 2^59 bytes in total. It generates the corresponding ciphertext and a tag of size tau=128.

## 56-bit LFSR56

We use a 56-bit LFSR56 for counter in Deoxys-AE3. LFSR56 is a one-to-one mapping LFSR56 : \[0, ... ,2^56-2\] -> {0,1}^56\\{(0)_56} defined as follows. Let F\_56(x) be the lexicographically-first polynomial among the the irreducible degree 56 polynomials of a minimum number of coefficients. Specifically F\_56(x) = x^56 + x^7 + x^4 + x^2 + 1 and LFSR56(D) = 2^D mod F\_56(x).

Note that we use LFSR56(D) as a block counter, so most of the time D changes incrementally with a step of 1, and this enables LFSR56(D) to generate a sequence of 2^56-1 pairwise-distinct values. From an implementation point of view, it should be implemented in the sequence form, x\_{i+1} = 2x\_i mod F\_56(x).

Let (z\_55 \|\| z\_54 \|\| ... \|\| z\_1 \|\| z\_0) denote the state of the 56-bit LFSR. In Deoxys-AE3, LFSR56 is initialized to 1 mod F\_56(x), i.e., ((0)_7 \|\| 1 \|\| (0)_48), in little-endian format. Incrementation of LFSR56 is defined as follows:

* z\_i = z\_{i-1} for i in [0, ... ,55]\\{7,4,2,0}
* z\_7 = z\_6 ^ z\_55
* z\_4 = z\_3 ^ z\_55
* z\_2 = z\_1 ^ z\_55
* z\_0 = z\_55

Below we write LFSR56(D) the state of LFSR56 when clocked D times.



## Deoxys-AE3 encryption

The mode is divided into two independant parts: the first part handling the encryption of the message, and the second part handing the authentication of the ciphertext and the associated data.

~~~
deoxys_AE3_encrypt(K, N, A, M):

  P = (0)_128
  con1 = (66)_8
  con2 = (64)_8
  con3 = (65)_8
  con4 = (68)_8
  theta = (1)_8 || (0)_120
  con5 = (2)_8 || (0)_120

  # Handling empty message
  if M == epsilon then
     C = epsilon
     m = 0
     end

  # 1. Message Encryption
  M[1] || ... || M[m] <- M with 0<|M[m]|<=128 and |M[i]|=128 for i=1,...,m-1
  S = TBC[(0)_56||con1||(0)_64||P||K](N)
  
  for i = 1 upto m-1
     C[i] = TBC[LFSR56(i-1)||con2||(0)_64||P||S](N) ^ M[i]
     S = TBC[LFSR56(i-1)||con3||(0)_64||P||S](N)
     end

  #the last block
  len = |M[m]|
  C[m] = trunc_len(TBC[LFSR56(m-1)||con2||(0)_64||P||S](N)) ^ M[m]


  # 2. Hashing Associated Data & Ciphertext
  U <- ipad*_128(A) || ipad*_128(C) || N || LFSR56(m)
  U <- ipad_256(U)
  U[1] || ... || U[u] <- U with |U[i]|=256
  L = (0)_128
  R = (0)_128
  theta = (1)_8 || (0)_120
  for i = 1 upto u - 1
     L = TBC[R || U[i]](L) ^ L
     R = TBC[R || U[i]](L ^ theta) ^ L ^ theta
     end
     
  L = L ^ con5
  L = TBC[R || U[i]](L) ^ L
  R = TBC[R || U[i]](L ^ theta) ^ L ^ theta

  # 3. Tag Generation
  tag = TBC[(0)_56||con4||(0)_64||R||K](L)
  return (C[1] || ... || C[m] , tag)

~~~


## Deoxys-AE3 decryption

~~~
deoxys_AE3_decrypt(K, N, A, C, tag):

  P = (0)_128
  con1 = (66)_8
  con2 = (64)_8
  con3 = (65)_8
  con4 = (68)_8
  theta = (1)_8 || (0)_120
  con5 = (2)_8 || (0)_120
  
  C[1] || ... || C[m] <- C with 0<|C[m]|<=128 and |C[i]|=128 for i=1,...,m-1

  # 1. Hashing Associated Data & Ciphertext for verification
  U <- ipad*_128(A) || ipad*_128(C) || N || LFSR56(m)
  U <- ipad_256(U)
  U[1] || ... || U[u] <- U with |U[i]|=256
  L = (0)_128
  R = (0)_128
  theta = (1)_8 || (0)_120
  for i = 1 upto u - 1
     L = TBC[R || U[i]](L) ^ L
     R = TBC[R || U[i]](L ^ theta) ^ L ^ theta
     end
     
  L = L ^ con5
  L = TBC[R || U[i]](L) ^ L
  R = TBC[R || U[i]](L ^ theta) ^ L ^ theta
  
  # 2. Verification
  L' = TBC-1[(0)_56||con4||(0)_64||R||K](tag)
  if L' != L then
     return invalid
     end 
  
  # 3. Decryption when L' == L
  S = TBC[(0)_56||con1||(0)_64||P||K](N)
  
  for i = 1 upto m-1
     M[i] = TBC[LFSR56(i-1)||con2||(0)_64||P||S](N) ^ C[i]
     S = TBC[LFSR56(i-1)||con3||(0)_64||P||S](N)
     end

  #the last block
  len = |C[m]|
  M[m] = trunc_len(TBC[LFSR56(m-1)||con2||(0)_64||P||S](N)) ^ C[m]

  return (M[1] || ... || M[m] || M*)
~~~

## Deoxys-AE3 test vectors

We provide below some test vectors for Deoxys-AE3, in hexadecimal display.

~~~~ 
Key:        85d6fd59 34703792 d0cb9ff2 f0ad3582
Nonce:      56960683 4c0e8a32 877fd47f 241f926b
AD:
plaintext:
ciphertext:
tag:        6bd43609 7e75f2d4 e2b5b476 93094d7a

Key:        85d6fd59 34703792 d0cb9ff2 f0ad3582
Nonce:      56960683 4c0e8a32 877fd47f 241f926b
AD:         55ecdd23 867c43
plaintext:  3aa1a9dc a69e75
ciphertext: 675c73e1 157d40
tag:        58bed416 b1746aaf 144c6802 5c939b6d

Key:        85d6fd59 34703792 d0cb9ff2 f0ad3582
Nonce:      56960683 4c0e8a32 877fd47f 241f926b
AD:         55ecdd23 867c4336 007893f7 2a381799
plaintext:  3aa1a9dc a69e75ba cb769cb1 1e55f05f
ciphertext: 675c73e1 157d4023 9bed96f6 55adb576
tag:        f0fce3f3 6c9429b8 465adce1 098dd9b0

Key:        85d6fd59 34703792 d0cb9ff2 f0ad3582
Nonce:      56960683 4c0e8a32 877fd47f 241f926b
AD:         55ecdd23 867c4336 007893f7 2a381799 37b33ee2 ab
plaintext:  3aa1a9dc a69e75ba cb769cb1 1e55f05f 94f49664 1c
ciphertext: 675c73e1 157d4023 9bed96f6 55adb576 f5258b18 04
tag:        84b73cc9 d82bac4b 57282712 dd1a4185
~~~~ 


# Optional Features

## Weak Leakage-Resilient Key Protection Mechanism

For Deoxys-AE1 and Deoxys-AE2, one can simply first compute a temporary key K' = TBC\_K\[N \|\|(8)\_8\|\|(0)\_120 \] that will be used as secret key input for the AEAD mode. Note that the tweak input is ensured to be unique when the nonce is not repeating, as (8)\_8 is a domain separation reserved for that feature only. This precomputation allows a weak form of leakage resilience \[[ABF13](ABF13)\].

## Increasing Multi-User Security

It is well known that, authenticated encryptions suffer from the so-called multi-user security degradation \[[BT16](BT16)\]. The concrete interpretation is that, in a security system maintaining u encrypted session using different keys, one needs around 2^128/u data and times complexities to break the confidentiality and authenticity for one of the u sessions. Note that this does not contradict the single-user interpretation, that is, to break the confidentiality and authenticity for a specific encrypted session, one needs around 2^128 data and times complexities. Therefore, to select an encryption algorithm for a security protocol, one may want to consider variants with better multi-user security.

One can increase the multi-user security of Deoxys-AE1 and Deoxys-AE2 by randomly selecting an 128-bit public-key value PK and incorporating PK as tweak input to every call to the TBC during the encryption phase. This will effectivelly increase the multi-users security by approximately x/2 bits.

One can increase the multi-user security of Deoxys-AE3 by randomly selecting a 128-bit public-key value PK and modify the internal variables to P = PK, con1 = (69)\_8, con2 = (70)\_8, con3 = (71)\_8, con4 = (72)\_8, and U = ipad*_128(A) \|\| ipad*_128(C) \|\| N \|\| PK \|\| LFSR56(m). For a system using this Deoxys-AE3 variant, one needs around 2^112 data and times complexities to break a session among about 2^126 different sessions.


## Nonce-Protection Mechanism

For Deoxys-AE1 and Deoxys-AE2, one can protect the nonce by two constructions (basically TBC-based variations of the schemes proposed by Bellare et al. at CRYPTO 2019). TODO

This can be used to protect the public-key for increased multi-users security as well. 


## Forgery-Reuse Protection Mechanism

In the very unlikely event where a forgery is found, this forgery could be reused to directly create new forgeries in the case of Deoxys-AE1 and Deoxys-AE2. One can tame this effect by using the nonce in the tweak inputs of each TBC calls in the authentication part (this can be viewed as a layer on top of Deoxys-AE1 and Deoxys-AE2, where we simply take the nonce N as associated data or message input every two 128-bit block). With this protection enabled, a forgery for a given nonce will not provide any advantage in creating a forgery for a different nonce, as all TBC calls will be totally new and independent. Of course, in the nonce-misuse scenario, this protection does not improve the situation. The disadvantage is that the authentication part would become slower as less associated data or message blocks can be handled per TBC call. 


## Maximum Input Length / Efficiency Trade-off

A 128-bit counter is used in the authentication part of Deoxys-AE1 and Deoxys-AE2. If for an application, the user is ensured that the associated data and message inputs are limited to at most 2^x blocks, then the 128-x most significant bits from the counter can be reclaimed to handle more AD/M input in the authentication part, which provide efficiency improvement. 

## Larger Keys

One can use larger keys than 128 bits for Deoxys-AE1 and Deoxys-AE2 by using a TBC version with a larger tweakey size. 


# Security Considerations


## Deoxys AEAD Operating Modes

We give below a table providing the bounds for all modes, in the various settings. TODO

### Deoxys-AE1

Security of Deoxys-AE1 in the nonce-respecting scenario is very strong: confidentiality is perfectly guaranteed and the forgery probability is 2^(-tau), independently of the number of blocks of data in encryption/decryption queries made by the adversary. This is simply managed by ensuring that only unique tweaks are used as long at the nonce is not repeating. In the nonce-misuse scenario, no security is claimed for Deoxys-AE1.

### Deoxys-AE2

TODO

### Deoxys-AE3

In the nonce-respecting scenario, the probability to break confidentiality and integrity is roughly D/2^121+T/2^121, where D is the number of processed data blocks and T is the amount of offline computations. The security guarantees depend on the underlying TBC being secure against chosen-tweakey attacks. Thus, it is safe to use Deoxys-AE3 with Deoxys-TBC-384. On the other hand, if Deoxys-AE3 is used with a TBC that is not chosen-tweakey secure (e.g., see Appendix B in \[[BGPPS19](BGPPS19)\]), the security guarantees vanish.

For a certain message encrypted by a certain nonce, confidentiality disappears if this nonce got reused, while the probability to break integrity remains roughly D/2^121+T/2^121. However, when nonces are reused, the probability to break confidentiality (as well as integrity) of messages encrypted by unique (i.e., non-reused) nonces remains roughly D/2^121+T/2^121.


## Deoxys-TBC

The AES and AES-type ciphers have already been the subject of extensive analysis. As a result, the security of these ciphers against the most popular forms of cryptanalysis, the differential and the linear attacks (as well as their more advanced variants), is well understood. Deoxys-TBC naturally leverages these cryptanalysis efforts (see Deoxys-JoC article TODO) and the new analysis conducted on Deoxys-TBC concentrated on the main difference between AES and Deoxys-TBC: the tweakey schedule. The best attack at time of writing could only reach 11 of the 14 rounds of Deoxys-TBC-256 and 14 of the 16 rounds of Deoxys-TBC-384. If we consider a time complexity upper limit of 2^128 (since 128-bit keys are used), only 10 of the 14 rounds of Deoxys-TBC-256 can be attacked and only 12 of the 16 rounds of Deoxys-TBC-384. These attacks only consider the internal TBC primitive and even less rounds can be reached if one considers the entire AEAD scheme. This leaves a very confortable security margin for all AEAD modes proposed here. 


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


