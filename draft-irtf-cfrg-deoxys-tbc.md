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



--- abstract

This document defines the Deoxys-TBC tweakable block ciphers, which comes in two versions Deoxys-TBC-256 (256 bits of key and tweak material) and Deoxys-TBC-384 (384 bits of key and tweak material). They are based on the Advanced Encryption Standard round function to benefit from previous security analysis and deployed hardware acceleration. 

This document builds up on the definitions of the Advanced Encryption Standard in [FIPS-AES], and is meant to serve as a stable reference and an implementation guide.

--- middle

# Introduction

A tweakable block cipher (TBC) is a family of permutations parametrised by a secret key K and a public tweak value T. This document defines the Deoxys-TBC tweakable block ciphers: Deoxys-TBC-256 (providing 256 bits of key and tweak material) and Deoxys-TBC-384 (providing 384 bits of key and tweak material), both having a block size of 128 bits. 

They are based on the round function of the Advanced Encryption Standard (AES) block cipher and are actually very similar to AES: they can be viewed as a tweakable version of AES, where the key schedule has been updated and more rounds are used to properly handle the extra tweak input. The similarity with AES allows to benefit from the extensive security analysis already provided on the worldwide block encryption standard. Moreover, the reuse of the AES round function leverages the growing deployement of AES hardware acceleration. 

Tweakable block ciphers are very versatile and useful primitives that can be placed in specially crafted operating modes to provide advanced security features that would be harder to obtain with classical block ciphers. For example, a classical shortcomming of most block cipher-based operating modes is that they can only reach birthday-bound security 2^n/2 with respect to the block length n of the underlying primitive. In the case of AES with a 128-bit block size, this means that security is lost at 2^64 block cipher calls at best, which is low given modern security requirements (for 64-bit block ciphers, the situation would be even more problematic). In contrary, tweakable block ciphers can easily and efficiently build so-called beyond birthday-bound schemes, that guarantee a high security even for 2^n/2 data and beyond. 

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

The following notations are used throughout the document:
- n:		plaintext/ciphertext bit-length of the tweakable block cipher. In the case of Deoxys-TBC, we have n=128.
- k:		key bit-length of the tweakable block cipher. In the case of Deoxys-TBC, we have 128 ≤ k ≤ 256.
- t:		tweak bit-length of the tweakable block cipher. 
- Nr:	the number of rounds of the tweakable block cipher. In the case of Deoxys-TBC-256 we have Nr=14, while for Deoxys-TBC-384 we have Nr=16.
- ||:		concatenation of bit strings.
- a ← b:    replace the value of the variable a with the value of the variable b .
- ⊕:       	bitwise exclusive-OR operation.
- [i, … , j]: sequence of integers starting from i included, ending at j included, with a step of 1.

Deoxys-TBC-256 and Deoxys-TBC-384 propose a so-called tweakey input that can be utilized as key and/or tweak material, up to the user needs. Therefore, the user can freely choose which part of the tweakey is dedicated to key and/or tweak material. However, whatever combination of key/tweak size chosen by the user, it SHALL be such that the key size is at least 128 bits and at most 256 bits. This document describes the configuration where the tweakey input is loaded with the tweak first (least significant portion of the tweakey), and the key material after (most significant portion of the tweakey), i.e. tweakey = key || tweak.


Deoxys-TBC operate on blocks of 128 bits seen as a (4×4) matrix of bytes which are numbered
\[ 0  4  8 12 \]  
\[ 1  5  9 13 \]  
\[ 2  6 10 14 \]  
\[ 3  7 11 15 \]  
 
and a tweakey length of size 256 bits (for Deoxys-TBC-256) or 384 bits (for Deoxys-TBC-384). For Deoxys-TBC-256 the tweakey consists of a key of size k ≥ 128 and a tweak of size t ≤ 256-k. For Deoxys-TBC-384 the tweakey consists of a key of size k ≥ 128 and a tweak of size t ≤ 384-k. 

## Deoxys-TBC encryption

Let the composition MixBytes(ShiftRows(SubBytes(X))) represent an unkeyed AES round on a state X and we denote it AES_R(X). The encryption with Deoxys-TBC of a 128-bit plaintext P gives a 128-bit ciphertext C that is defined as: 

X\[0\] ← P  
X\[i+1\] ← AES_R(AddRoundTweakey(X\[i\] , STK\[i\])) for i in \[0, ... , Nr-1\]  
C ← AddRoundTweakey(X\[Nr\] , STK\[Nr\])  

where AddRoundTweakey(X, STK) is the operating consisting of XORing the 128-bit round sub-tweakey STK (defined further) to the internal state X. The number of rounds Nr is 14 for Deoxys-TBC-256 and 16 for Deoxys-TBC-384.  

## Deoxys-TBC decryption

Let the composition SubBytesInv(ShiftRowsInv(MixBytesInv(X))) represent an unkeyed AES inverse round on a state X and we denote it AES_R-1(X). The decryption with Deoxys-TBC of a 128-bit ciphertext C gives a 128-bit plaintext P that is defined as: 

X\[0\] ← C  
X\[i+1\] ← AES_R-1(AddRoundTweakey(X\[i\] , STK\[Nr-i\])) for i in \[0, ... , Nr-1\]  
P ← AddRoundTweakey(X\[Nr\] , STK\[0\])  


## Deoxys-TBC tweakey schedule

We denote TK the input tweakey state and we divide it into words of 128 bits. More precisely, in Deoxys-TBC-256, the size of TK is 256 bits with the first (most significant) 128 bits of TK being denoted W2, while the second W1. For Deoxys-TBC-384, the size of TK is 384 bits, with the first (most significant) 128 bits of TK being denoted W3, the second W2 and the third W1. Finally, we denote with STK\[i\] the sub-tweakey (a 128-bit word) that is added to the state at round i of the cipher during the AddRoundTweakey operation. For Deoxys-TBC-256, a sub-tweakey for round i is defined as: 
STK\[i\] = TK1\[i\]  ⊕ TK2\[i\]  ⊕ RC\[i\]  
whereas for the case of Deoxys-TBC-384 it is defined as:
STK\[i\] = TK1\[i\]  ⊕ TK2\[i\]  ⊕ TK3\[i\]  ⊕ RC\[i\]  
The 128-bit words TK1\[i\], TK2\[i\], TK3\[i\] are outputs produced by a tweakey schedule algorithm, initialized with TK1\[0\]=W1 and TK2\[0\]=W2 for Deoxys-TBC-256 (TK3\[i\] is ignored for Deoxys-TBC-256) and with TK1\[0\]=W1, TK2\[0\]=W2 and TK3\[0\]=W3 for Deoxys-TBC-384. The tweakey schedule algorithm uses two Linear-Feedback Shift Registers (LFSR) and is defined as:
TK1\[i+1\] = h(TK1\[i\]),  
TK2\[i+1\] = LFSR2(h(TK2\[i\])), 
TK3\[i+1\] = LFSR3(h(TK3\[i\])) in the case of Deoxys-TBC-384
where the byte permutation h is defined as:

\[ 0  4  8 12 \]        \[ 1  5  9 13 \]  
\[ 1  5  9 13 \]        \[ 6 10 14  2 \]  
\[ 2  6 10 14 \]  --->  \[11 15  3  7 \]  
\[ 3  7 11 15 \]        \[12  0  4  8 \]  

The LFSR2 and LFSR3 functions are the application of an LFSR to each of the 16 bytes of a tweakey 128-bit word. More precisely, the two LFSRs used are given below (x0 stands for the LSB of the cell and x7 for the MSB):
- LFSR2: (x7||x6||x5||x4||x3||x2||x1||x0) -->  (x6||x5||x4||x3||x2||x1||x0||x7⊕x5)  
- LFSR3: (x7||x6||x5||x4||x3||x2||x1||x0) -->  (x0⊕x6||x7||x6||x5||x4||x3||x2||x1)  

Finally, RC\[i\] are the key schedule round constants, and are defined as:
          \[ 1  RCON\[i\]  0  0 \]   
          \[ 2  RCON\[i\]  0  0 \]   
RC\[i\] = \[ 4  RCON\[i\]  0  0 \]   
          \[ 8  RCON\[i\]  0  0 \]    
          
where RCON\[i\] denotes the (i+15)-th key schedule constants of the AES. These constants are also given in hexadecimal notation below: 
i    0 | 1 | 2 | 3 | 4 | 5  
RCON\[i\]



# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

