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
- k:		key bit-length of the tweakable block cipher. 
- t:		tweak bit-length of the tweakable block cipher. 
- Nr:	the number of rounds of the tweakable block cipher. In the case of Deoxys-TBC-256 we have Nr=14, while for Deoxys-TBC-384 we have Nr=16
- ||:		concatenation of bit strings
- a ← b:    Replace the value of the variable a with the value of the variable b 
- ⊕:       	Bitwise exclusive-OR operation.
- [i, … , j]: Sequence of integers starting from i included, ending at j included, with a step of 1

Deoxys-TBC-256 and Deoxys-TBC-384 propose a so-called tweakey input that can be utilized as key and/or tweak material, up to the user needs. Therefore, the user can freely choose which part of the tweakey is dedicated to key and/or tweak material. However, whatever combination of key/tweak size chosen by the user, it SHALL be such that the key size is at least 128 bits and at most 256 bits. This document describes the configuration where the tweakey input is loaded with the tweak first (least significant portion of the tweakey), and the key material after (most significant portion of the tweakey), i.e. tweakey = key || tweak.



# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

