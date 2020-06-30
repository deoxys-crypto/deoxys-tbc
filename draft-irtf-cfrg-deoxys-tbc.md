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

normative:
  RFC2119:

informative:
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

  FIPS-197:
    target: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    title: "Advanced Encryption Standard (AES)"
    author: 
        org: National Institute of Standards and Technology
      
    seriesinfo: "FIPS PUB 197"
    date: 2001
    PDF: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf


  JNP14:
    target: https://eprint.iacr.org/2014/831.pdf
    title: "Tweaks and Keys for Block Ciphers: the TWEAKEY Framework"
    author: 
      -
        name: J. Jean 
      -  
        name: I. Nikolić
      -  
        name: T. Peyrin
    seriesinfo: "Proceedings of the 22nd International Conference on the Theory and Application of Cryptology and Information Security – ASIACRYPT 2014, Lecture Notes in Computer Science 8874, pp.274-288"
    date: 2014
    PDF: https://eprint.iacr.org/2014/831.pdf

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
* \|\|: concatenation of bit strings.
* a ← b: replace the value of the variable a with the value of the variable b.
* XOR: bitwise exclusive-OR operation.
* \[i, ... , j\]: sequence of integers starting from i included, ending at j included, with a step of 1.



# The Deoxys-TBC Tweakable Block Ciphers

We describe here the Deoxys-TBC tweakable block ciphers, as published in \[[JNP14](JNP14)\] and JNPS14. Deoxys-TBC-256 and Deoxys-TBC-384 propose a so-called tweakey input that can be utilized as key and/or tweak material, up to the user needs. Therefore, the user can freely choose which part of the tweakey is dedicated to key and/or tweak material. However, whatever combination of key/tweak size chosen by the user, it SHALL be such that the key size is at least 128 bits and at most 256 bits. This document describes the configuration where the tweakey input is loaded with the tweak first (least significant portion of the tweakey), and the key material after (most significant portion of the tweakey), i.e. tweakey = key \|\| tweak.

Deoxys-TBC operate on blocks of 128 bits seen as a (4×4) matrix of bytes which are numbered

~~~~ 
[ 0  4  8 12 ]
[ 1  5  9 13 ]
[ 2  6 10 14 ]
[ 3  7 11 15 ]
~~~~ 

and a tweakey length of size 256 bits (for Deoxys-TBC-256) or 384 bits (for Deoxys-TBC-384). For Deoxys-TBC-256 the tweakey consists of a key of size k ≥ 128 and a tweak of size t ≤ 256-k. For Deoxys-TBC-384 the tweakey consists of a key of size k ≥ 128 and a tweak of size t ≤ 384-k. 

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


# The Deoxys-I\* AEAD Operating Mode

This mode is an adaptation of the Deoxys-I AEAD operating mode from \[[JNPS14](JNPS14)\], the only difference being that Deoxys-TBC-384 is used instead of Deoxys-TBC-256, in order to handle more data per TBC call during the authentication part, allowing longer nonce and longer maximum data size. 

This mode takes a secret key of 128 bits, nonces of 128 bits and can handle associated data and message inputs of size up to 2^128 bits. It generates the corresponding ciphertext and a tag of size tau<=128.

## Deoxys-I\* encryption

## Deoxys-I\* decryption

## Deoxys-I\* pseudocode

## Deoxys-I\* test vectors



# The Deoxys-II\* AEAD Operating Mode

This mode is an adaptation of the Deoxys-II AEAD operating mode from \[[JNPS14](JNPS14)\], the only difference being that Deoxys-TBC-384 is used instead of Deoxys-TBC-256, in order to handle more data per TBC call during the authentication part, while getting better security bounds.  

This mode takes a secret key of 128 bits, nonces of 128 bits and can handle associated data and message inputs of size up to 2^128 bits. It generates the corresponding ciphertext and a tag of size tau<=128.

## Deoxys-II\* encryption

## Deoxys-II\* decryption

## Deoxys-II\* pseudocode

## Deoxys-II\* test vectors



# The Deoxys-III\* AEAD Operating Mode

This mode is an adaptation of the TEDT AEAD operating mode from \[[BGPPS19](BGPPS19)\], the only difference being that Deoxys-TBC-384 is used instead of Deoxys-TBC-256, in order to handle more data per TBC call during the authentication part, allowing longer nonce and longer maximum data size.  

This mode takes a secret key of 128 bits, nonces of 128 bits and can handle associated data and message inputs of size up to 2^128 bits. It generates the corresponding ciphertext and a tag of size tau<=128.

## Deoxys-III\* encryption

## Deoxys-III\* decryption

## Deoxys-III\* pseudocode

## Deoxys-III\* test vectors


# Optional Features

For Deoxys-I\* and Deoxys-II\*, we propose two optional features: a weak leakage-resilient key protection mechanism and a nonce-hiding mechanism. TODO 


# Security Considerations


## Deoxys-TBC



## Deoxys AEAD Operating Modes

We give below a table providing the bounds for all modes, in the various settings. TODO

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

