Cl0p ELF Variant Files Decryptor
==============

Python3 script which decrypts files encrypted by flawed Cl0p ELF variant.

More info regarding Cl0p ELF variant and how decryptor was created at [SentinelOne post](https://s1.ai/Clop-ELF).

### Usage

```
python3 clop_linux_file_decr.py --help
========================================
SentinelOne Cl0p ELF variant Decryptor.
Author: @Tera0017/@SentinelOne
Link: https://s1.ai/Clop-ELF
========================================
usage: clop_linux_file_decr.py [-h] [--elfile ELFILE] [--keys KEYS] [--rc4key RC4KEY]

Python3 script which decrypts files encrypted by flawed Cl0p ELF variant. More info regarding Cl0p
ELF variant and how decryptor was created at https://s1.ai/Clop-ELF

optional arguments:
  -h, --help       show this help message and exit
  --elfile ELFILE  ELF Cl0p Binary, is used to retrieve "RC4 master key" else default is used for
                   decryption, or provided with "--rc4key" argument.
  --keys KEYS      File containing result of "$ find / -name *.$cl0p_extension -print 2>/dev/null >
                   cl0p_keys.txt". Run with sudo if needed.
  --rc4key RC4KEY  RC4 master key for decryption of clop key files. If --elf is provided script will
                   dynamically retrieve it.

author:@Tera0017/@SentinelOne
```
<br>

#### Requirements

* **arc4**, tested version "0.0.4"

### Support

In case something is wrong or not working as supposed to please feel free to contact [@Tera0017](https://twitter.com/Tera0017).