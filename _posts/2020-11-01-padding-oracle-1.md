---
title: 'Padding Oracle Vulnerabilities Under The Hood - Part 1: Introduction'
layout: post
date: '2020-11-01 12:26:29'
---

## 1. Introduction
This blog post covers the following;
*  Overview of AES modes of operation.
*  How padding is used and padding oracle bugs.
*  A demo application which is vulnerable to padding oracle attack. 

## 2.  AES Modes of Operation

This blog post does not cover AES encryption, there are many resources online.
In-short, The AES encryption can be "used" as follows:

The key can be derived from the encryption password using a key-derivation function (Scrypt, Bcrypt, PBKDF2, Argon2).

AES encryption may return an IV (depends on block mode), MAC (depends on block mode) and ciphertext by using the encryption key, algorithm parameters and the plaintext as input.

The AES Decryption Process is also similar; it typically takes ciphertext, IV and encryption key then it returns the plaintext.

Algorithm parameters define block mode, encryption key, MAC algorithm. It may also define Scrypt parameters if it is used.

The Block ciphers convert the plaintext into the ciphertext by taking fixed size of blocks at a time. Stream ciphers Convert the plaintext into the ciphertext by taking 1 byte of plaintext at a time.

The block cipher modes are designed to apply a single-block encryption or decryption to an amount of data which is larger than the block. 


### 2.1 ECB - Electronic Code Book mode

The simplest and the weakest mode hence it is not recommended. 

Basically, it splits into blocks as the length of the block size. Then it encrypts every block with the same key and same algorithm.

Scheme of encryption and decryption are shared below:

**AES-ECB Encryption**:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png)

Credit: [https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png)

**AES-ECB Decryption**:

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Credit: [https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

When we encrypt the same plaintext, we get the same ciphertext that means this algorithm is not [semantically secure](https://crypto.stackexchange.com/questions/30130/why-is-semantically-secure-important-for-cryptosystems).

Let me try to explain the famous ECB Penguin then it would be better to understand why IVs are used within AES-CBC encryption.


**What is wrong with The Famous ECB Penguin?**

The famous "Tux" image is actually known as "The ECB Penguin", 

![https://upload.wikimedia.org/wikipedia/commons/f/f0/Tux_ecb.jpg](https://upload.wikimedia.org/wikipedia/commons/f/f0/Tux_ecb.jpg)

Credit: https://en.wikipedia.org/wiki/Wikipedia:Featured_picture_candidates/April-2004#Tux_ecb.jpg

Let's say we store "header" of the TUX image file seperately then encrypt the rest of the file with AES-ECB encryption; when we merge the header and encrypted binary again we are able to understand what it is. It happens because when same key and data is used via AES-ECB encryption it gives always same output. Let's say white is going to be yellow and all of blacks are going to be green then it is possible to guess what is in a picture.

If you want to understand better, you can check following repository on Github:
[https://github.com/tkeliris/ecb-penguin](https://github.com/tkeliris/ecb-penguin)



One well known example is [Adobe's Data Breach (3DES-ECB)](https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/)

![https://imgs.xkcd.com/comics/encryptic.png](https://imgs.xkcd.com/comics/encryptic.png)

So far so good, that means an attacker can demonstrate an attack even he/she doesn't have the plaintext or the encryption key. 

Shannon's Principles [1](https://ieeexplore.ieee.org/document/6769090) [2](http://pages.cs.wisc.edu/~rist/642-spring-2014/shannon-secrecy.pdf) and Perfect Forward Secrecy are not covered within this blog post.


### 2.2. CBC - Cipher Block Chaining mode

The Cipher Block Chaining mode requires an input to split into blocks. 
Pading to a multiple of block size is needed after the last block in CBC.
ECB also works like CBC, main difference between them is CBS has an Initialization Vector (IV). With help of the IV randomness on ciphertext is  increased thus we do not get same ciphertext for same plaintexts (in ideal universe).

CBC encryption and decryption schemes are shared in more detail on sections 6.1. and 6.2 of this blog post.

Same TUX image and encrpyted version with AES-CBC:

**Plaintext:**

![](https://upload.wikimedia.org/wikipedia/commons/5/56/Tux.jpg)

Credit: [https://upload.wikimedia.org/wikipedia/commons/5/56/Tux.jpg](https://upload.wikimedia.org/wikipedia/commons/5/56/Tux.jpg)


**AES-CBC Result:**

![](https://upload.wikimedia.org/wikipedia/commons/a/a0/Tux_secure.jpg)

Credit: [https://upload.wikimedia.org/wikipedia/commons/a/a0/Tux_secure.jpg](https://upload.wikimedia.org/wikipedia/commons/a/a0/Tux_secure.jpg)

### 2.3. Others 

There are many others, but they are not covered in this blog post.  
CTR (Counter), GCM (Galois/Counter Mode), CFB, OFB, EAX, CCM and so on. 


## 3. Padding Scheme

When it splits plaintext into blocks, then what happens when it does not fit?
> I mean, what happens in case "(if N%16 != 0) == True" where N is length of the  ciphertext?

This is why/when padding is used. A padding is an additional byte addition to a block of a ciphertext.

For example the lenght of a given plaintext is 18 and the block size is 16. 
Then 14 times "padding bytes" should be added"
Plaintext: QWEASDZXCQWEASDZEW00000000000000

{QWEASDZXCQWEASDZ}-{EW00000000000000}
    (1st Block)      (2nd Block)

Padding Bytes: "00000000000000"

But there should be a standard for padding, so RSA implemented PKCS#5 and PKCS#7.

### 3.1. PKCS and RSA

Public-Key Cryptography Standards are explained on [The RFC number 3447](https://tools.ietf.org/html/rfc3447#page-70)

They explain and standardize use of the [cryptography techniques](https://en.wikipedia.org/wiki/PKCS).


### 3.2. PKCS5 and PKCS7

Basically, they are identical. PKCS#5 is for 8-byte block sizes, but PKCS#7 can work from from 1 to 255 bytes block sizes.

The algorithm is as follows:

1. How many pads you add, you need to use that number 
2. Calculate size of the padding:
    pad_length = 16 - (len(data) % 16)
3. if [XXXXXXXXXXXOOOOO] then; pad_length = 5 
4. The last bytes are related to the size of padding:
    if 5 then add x05 for 5 times.
    
		Eg: b'do_not_use_cbcdo_not_use_cbcdo_not_use_cbc!\x05\x05\x05\x05\x05'
5. If there is no padding needed than create new block and fill with 0x10. **This means; you always have padding.**
    
		Eg: b'do_not_use_cbcdo_not_use_cbcdo_not_use_cbc12345!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

You can check following link for a good explanation: 
[https://crypto.stackexchange.com/questions/66646/aes-cbc-padding-why-always-attach-16x-0x10-pad](https://crypto.stackexchange.com/questions/66646/aes-cbc-padding-why-always-attach-16x-0x10-pad)

## 4. Padding Oracle Vulnerabilities

### 4.1. What is an Oracle in Cryptography?

**There is no any relationship between Oracle Software Company and Padding Oracle Vulnerabilities!** 

The answer of [Thomas Pornin](http://www.bolet.org/~pornin/cv-en.html) on stackexchange question explains very good:
[https://security.stackexchange.com/a/10621](https://security.stackexchange.com/a/10621)

From his answer: 
> "...an oracle is any system which can give some extra information on a system, which otherwise would not be available."


### 4.2. When The Padding Oracle Vulnerabilities Occur?

A padding error occurs when the PKCS#7 or #5 standart is not followed. Eg: If the decrypted ciphertext ends without a valid format like: ... 01 02 03. (This example would end like: ... 03 03 03 to be named as "valid", because the number of the padding bytes are 3)

There are some conditions for Padding Oracle vulnerabilies:

1. Application throws an error or delays may happen when an invalid padding on ciphertext. (Server does not need to throw message/exception "Invalid Padding", by checking response time it might be possible to exploit like Time-Based SQL Injections.) [Check 5:40 of this video.](https://www.coursera.org/lecture/crypto/cbc-padding-attacks-8s23o)
2. Attacker has direct or indirect access to an oracle function. For instance the attacker can send the manipulated ciphertext or manupulated IV to server which hands over the data to the oracle function.
3. Attacker does not need The Encryption Key.
4. Attacker does not need to recover The Encryption Key.

By using Padding Oracle vulnerabilities an attacker can;
1. Recover The Plaintext.
2. Create a valid Ciphertext.

An example demo app is shared on Section 6.3 of this blog post.


## 5. Some Known Padding Oracle Vulnerabilities

Let me sort some of them below:

1. [CVE-2014-3566 aka. POODLE](https://www.openssl.org/~bodo/ssl-poodle.pdf) (Paper of Bodo Möller, Thai Duong, Krzysztof Kotowicz from Google)
2. [https://support.citrix.com/article/CTX240139](https://support.citrix.com/article/CTX240139)
3. [https://issues.apache.org/jira/browse/SHIRO-721](https://issues.apache.org/jira/browse/SHIRO-721) (aka. CVE-2019-12422)
4. [https://github.com/MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit](https://github.com/MostafaSoliman/Oracle-OAM-Padding-Oracle-CVE-2018-2879-Exploit)
5. [https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/](https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/)
6. [http://netifera.com/research/poet/ieee-aspnetcrypto.pdf](http://netifera.com/research/poet/ieee-aspnetcrypto.pdf) (Paper of Thai Duong of Google Security and Juliano Rizzo of Netifera)
7. [A Known Old .Net Bug aka. MS10-070](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-070?redirectedfrom=MSDN)


## 6. Vulnerable Application Example

As I mentioned earlier, CBC has an IV at the beginning as a difference to ECB.

### 6.1. CBC Encryption:
![https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png)

Credit: [https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png)

### 6.2. CBC Decryption:
![https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png)

Credit: [https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png)

### 6.3. Demo Application:

I wrote a demo web application which encrypts secret message with random IV and random Key by using AES-CBC.
It is possible to get the base64encoded(IV+ciphertext) from "/" root path. 

![]({{ site.url }}/assets/padding-oracle/web-app.png)

The '/decrypt?ciphertext=' path and parameter are used to decrypt the sent ciphertext. The application returns '401 HTTP Status Code' when there is a padding error:

```py
@app.route('/decrypt')
def padding_oracle():
    """
    Function for decryption operation, receives GET parameter 'ciphertext'.
    :return: HTTP Status 401 if the padding is incorrect otherwise return valid message.
    """
    get_param = request.args.get('ciphertext')
    print(get_param)
    ciphertext = b64decode(get_param)
    if cipher.decrypt(ciphertext) != 0:
        return "Padding is valid."
    else:
        abort(401) 
```


The [aes_lib.py](https://github.com/cemonatk/padding-oracle-demo/blob/main/aes_lib.py) has many comments to explain what goes on behind the scenes. 

For instance, the custom "un-pad" and "pad" methods are shared below:

```py

    def pkcs7_pad(self, data):
        """
        Pading to a multiple of 16 by following RFC.
        https://tools.ietf.org/html/rfc2315

        :param self: self object
        :param data: data that should be unpadded.
        :return: data with removed padding bytes.
        """
        # Calculate size of the padding
        pad_length = 16 - (len(data) % 16)
        # if [XXXXXXXXXXXXOOOO] then; pad_length = 4 
        # The last bytes are related to the size of padding. How many pads you add, you need to use that number.
        data += bytes([pad_length]) * pad_length
        # if 4 then add x04 for 4 times.
        return data

    def pkcs7_unpad(self, data):
        """
        Unpadding with same methodology which is used on pkcs_pad()
        :param self: self object
        :param data: data that should be unpadded.
        :return: data with removed padding bytes.
        """
        # The last byte declares the number of padding bytes.
        padding = data[-1]
        # Check padding length
        if padding == 0 or padding > 16:
            return 0 # Welcome Oracle! 
        for i in range(1, padding):
            if data[-i-1] != padding:
                return 0 # Welcome Oracle! 
        return data[:-padding]
``` 

You can find the source code on my github repository:
[https://github.com/cemonatk/padding-oracle-demo](https://github.com/cemonatk/padding-oracle-demo)


## 7. Resources
1. [https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html)
2. [https://csrc.nist.gov/projects/block-cipher-techniques](https://csrc.nist.gov/projects/block-cipher-techniques)
3. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
4. [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
5. [https://tools.ietf.org/html/rfc8018#appendix-B.2.5](https://tools.ietf.org/html/rfc8018#appendix-B.2.5)
6. [https://www.ietf.org/rfc/rfc2315.txt](https://www.ietf.org/rfc/rfc2315.txt)
7. [https://www.ibm.com/support/knowledgecenter/en/linuxonibm/com.ibm.linux.z.wskc.doc/wskc_c_l0wskc58.html](https://www.ibm.com/support/knowledgecenter/en/linuxonibm/com.ibm.linux.z.wskc.doc/wskc_c_l0wskc58.html)
8. [https://ieeexplore.ieee.org/document/6769090](https://ieeexplore.ieee.org/document/6769090)
