#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tbl_crypto.py — KnightOnline .tbl custom-DES decryptor (BIREBIR port).

Knight Online'in .tbl veri dosyalari, standart DES'in IP/FP'siz (Initial/Final
Permutation kaldirilmis) 16-round Feistel varyanti + 4-round bir KDF ile
sifrelenir. Bu modul, client'in bellek imajindan reverse edilmis algoritmayi
ve tum sabitleri (E, P, PC-2, shift, 8 S-box, MAGIC, 4 STRENGTH state, key string)
Python'a tasir. Sadece stdlib kullanir, harici bagimlilik yok.

Reverse edilen fonksiyonlar (VA, image_base=0x400000):
  FUN_006221b0  master decrypt / framing
  FUN_006224d0  16-round Feistel (IP/FP YOK), decrypt = subkey ters sira
  FUN_00622820  key schedule expand (28-bit C/D left-rotate + PC-2)
  FUN_006223a0  KDF orkestrasyonu (4 round)
  FUN_00622430  key-byte -> state dagitimi (bit XOR, MSB-first, null-aware)

Dosya cercevesi (framing):
  [0..16)   MAGIC (16 byte sabit)
  [16..20)  decrypted_size (u32)  -> cikti bu boya truncate edilir
  [20..]    sifreli payload, 8-byte (64-bit) ECB bloklari (uzunluk 8'in kati)

Veri bloklari "bit-sliced": her byte 64-elemanli {0,1} dizisine MSB-first acilir.
S-box ciktilari da bit-sliced 4-bit'tir. Tum islemler bit dizileri uzerinde.

Kullanim:
  from tbl_crypto import decrypt_tbl
  payload = decrypt_tbl("C:/NTTGame/KnightOnlineEn/Data/Skill_Magic_1.tbl")
"""

import sys
import struct

# ---------------------------------------------------------------------------
# SABITLER — client bellek imajindan okunmus, standart DES ile capraz-dogrulanmis.
# ---------------------------------------------------------------------------

# MAGIC @VA 0x00fee7f0 (16 byte). Dosyanin ilk 16 byte'i bununla eslesmeli.
MAGIC = bytes([76, 38, 67, 127, 128, 241, 87, 152, 121, 252, 175, 38, 134, 214, 32, 142])

# KDF key string — load fn stack'te kuruyor, null-terminated. 15 byte.
KEY_STRING = b"8sgpV&22dsdLg3k"

# E-expansion @VA 0x00fee790 (48 byte). Her deger 1..32 arasi bit indeksi (R'nin biti).
# round fn'de erisim: data[31 + E[i]] -> data[32..63] = R (sag yari).
E_EXPANSION = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15,
               16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28,
               29, 28, 29, 30, 31, 32, 1]

# P-permutation @VA 0x00fedf70 (32 byte). Standart DES P.
# (round fn'de &DAT_00fedf71 olarak -1 indeksli gecer; gercek tablo @fedf70.)
P_PERM = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32,
          27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# PC-2 @VA 0x00fee7c0 (48 byte). Standart DES PC-2 (56-bit C||D -> 48-bit subkey).
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13,
       2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42,
       50, 36, 29, 32]

# Shift schedule @VA 0x00fee800 (16 x u32). Standart DES rotate miktarlari.
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 S-box @VA: S0=0xfee690 ... S7=0xfedf90. Her biri 64 entry x 4-bit (bit-sliced, MSB-first).
# Index = ((((((row_hi*2|row_lo)*2|c0)*2|c1)*2|c2)*2|c3))  (standart DES: row=t0,t5 col=t1..t4).
SBOXES = [[[1, 1, 1, 0], [0, 1, 0, 0], [1, 1, 0, 1], [0, 0, 0, 1], [0, 0, 1, 0], [1, 1, 1, 1], [1, 0, 1, 1], [1, 0, 0, 0], [0, 0, 1, 1], [1, 0, 1, 0], [0, 1, 1, 0], [1, 1, 0, 0], [0, 1, 0, 1], [1, 0, 0, 1], [0, 0, 0, 0], [0, 1, 1, 1], [0, 0, 0, 0], [1, 1, 1, 1], [0, 1, 1, 1], [0, 1, 0, 0], [1, 1, 1, 0], [0, 0, 1, 0], [1, 1, 0, 1], [0, 0, 0, 1], [1, 0, 1, 0], [0, 1, 1, 0], [1, 1, 0, 0], [1, 0, 1, 1], [1, 0, 0, 1], [0, 1, 0, 1], [0, 0, 1, 1], [1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [1, 1, 1, 0], [1, 0, 0, 0], [1, 1, 0, 1], [0, 1, 1, 0], [0, 0, 1, 0], [1, 0, 1, 1], [1, 1, 1, 1], [1, 1, 0, 0], [1, 0, 0, 1], [0, 1, 1, 1], [0, 0, 1, 1], [1, 0, 1, 0], [0, 1, 0, 1], [0, 0, 0, 0], [1, 1, 1, 1], [1, 1, 0, 0], [1, 0, 0, 0], [0, 0, 1, 0], [0, 1, 0, 0], [1, 0, 0, 1], [0, 0, 0, 1], [0, 1, 1, 1], [0, 1, 0, 1], [1, 0, 1, 1], [0, 0, 1, 1], [1, 1, 1, 0], [1, 0, 1, 0], [0, 0, 0, 0], [0, 1, 1, 0], [1, 1, 0, 1]],
          [[1, 1, 1, 1], [0, 0, 0, 1], [1, 0, 0, 0], [1, 1, 1, 0], [0, 1, 1, 0], [1, 0, 1, 1], [0, 0, 1, 1], [0, 1, 0, 0], [1, 0, 0, 1], [0, 1, 1, 1], [0, 0, 1, 0], [1, 1, 0, 1], [1, 1, 0, 0], [0, 0, 0, 0], [0, 1, 0, 1], [1, 0, 1, 0], [0, 0, 1, 1], [1, 1, 0, 1], [0, 1, 0, 0], [0, 1, 1, 1], [1, 1, 1, 1], [0, 0, 1, 0], [1, 0, 0, 0], [1, 1, 1, 0], [1, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 1], [1, 0, 1, 0], [0, 1, 1, 0], [1, 0, 0, 1], [1, 0, 1, 1], [0, 1, 0, 1], [0, 0, 0, 0], [1, 1, 1, 0], [0, 1, 1, 1], [1, 0, 1, 1], [1, 0, 1, 0], [0, 1, 0, 0], [1, 1, 0, 1], [0, 0, 0, 1], [0, 1, 0, 1], [1, 0, 0, 0], [1, 1, 0, 0], [0, 1, 1, 0], [1, 0, 0, 1], [0, 0, 1, 1], [0, 0, 1, 0], [1, 1, 1, 1], [1, 1, 0, 1], [1, 0, 0, 0], [1, 0, 1, 0], [0, 0, 0, 1], [0, 0, 1, 1], [1, 1, 1, 1], [0, 1, 0, 0], [0, 0, 1, 0], [1, 0, 1, 1], [0, 1, 1, 0], [0, 1, 1, 1], [1, 1, 0, 0], [0, 0, 0, 0], [0, 1, 0, 1], [1, 1, 1, 0], [1, 0, 0, 1]],
          [[1, 0, 1, 0], [0, 0, 0, 0], [1, 0, 0, 1], [1, 1, 1, 0], [0, 1, 1, 0], [0, 0, 1, 1], [1, 1, 1, 1], [0, 1, 0, 1], [0, 0, 0, 1], [1, 1, 0, 1], [1, 1, 0, 0], [0, 1, 1, 1], [1, 0, 1, 1], [0, 1, 0, 0], [0, 0, 1, 0], [1, 0, 0, 0], [1, 1, 0, 1], [0, 1, 1, 1], [0, 0, 0, 0], [1, 0, 0, 1], [0, 0, 1, 1], [0, 1, 0, 0], [0, 1, 1, 0], [1, 0, 1, 0], [0, 0, 1, 0], [1, 0, 0, 0], [0, 1, 0, 1], [1, 1, 1, 0], [1, 1, 0, 0], [1, 0, 1, 1], [1, 1, 1, 1], [0, 0, 0, 1], [1, 1, 0, 1], [0, 1, 1, 0], [0, 1, 0, 0], [1, 0, 0, 1], [1, 0, 0, 0], [1, 1, 1, 1], [0, 0, 1, 1], [0, 0, 0, 0], [1, 0, 1, 1], [0, 0, 0, 1], [0, 0, 1, 0], [1, 1, 0, 0], [0, 1, 0, 1], [1, 0, 1, 0], [1, 1, 1, 0], [0, 1, 1, 1], [0, 0, 0, 1], [1, 0, 1, 0], [1, 1, 0, 1], [0, 0, 0, 0], [0, 1, 1, 0], [1, 0, 0, 1], [1, 0, 0, 0], [0, 1, 1, 1], [0, 1, 0, 0], [1, 1, 1, 1], [1, 1, 1, 0], [0, 0, 1, 1], [1, 0, 1, 1], [0, 1, 0, 1], [0, 0, 1, 0], [1, 1, 0, 0]],
          [[0, 1, 1, 1], [1, 1, 0, 1], [1, 1, 1, 0], [0, 0, 1, 1], [0, 0, 0, 0], [0, 1, 1, 0], [1, 0, 0, 1], [1, 0, 1, 0], [0, 0, 0, 1], [0, 0, 1, 0], [1, 0, 0, 0], [0, 1, 0, 1], [1, 0, 1, 1], [1, 1, 0, 0], [0, 1, 0, 0], [1, 1, 1, 1], [1, 1, 0, 1], [1, 0, 0, 0], [1, 0, 1, 1], [0, 1, 0, 1], [0, 1, 1, 0], [1, 1, 1, 1], [0, 0, 0, 0], [0, 0, 1, 1], [0, 1, 0, 0], [0, 1, 1, 1], [0, 0, 1, 0], [1, 1, 0, 0], [0, 0, 0, 1], [1, 0, 1, 0], [1, 1, 1, 0], [1, 0, 0, 1], [1, 0, 1, 0], [0, 1, 1, 0], [1, 0, 0, 1], [0, 0, 0, 0], [1, 1, 0, 0], [1, 0, 1, 1], [0, 1, 1, 1], [1, 1, 0, 1], [1, 1, 1, 1], [0, 0, 0, 1], [0, 0, 1, 1], [1, 1, 1, 0], [0, 1, 0, 1], [0, 0, 1, 0], [1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 1], [1, 1, 1, 1], [0, 0, 0, 0], [0, 1, 1, 0], [1, 0, 1, 0], [0, 0, 0, 1], [1, 1, 0, 1], [1, 0, 0, 0], [1, 0, 0, 1], [0, 1, 0, 0], [0, 1, 0, 1], [1, 0, 1, 1], [1, 1, 0, 0], [0, 1, 1, 1], [0, 0, 1, 0], [1, 1, 1, 0]],
          [[0, 0, 1, 0], [1, 1, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 1, 1, 1], [1, 0, 1, 0], [1, 0, 1, 1], [0, 1, 1, 0], [1, 0, 0, 0], [0, 1, 0, 1], [0, 0, 1, 1], [1, 1, 1, 1], [1, 1, 0, 1], [0, 0, 0, 0], [1, 1, 1, 0], [1, 0, 0, 1], [1, 1, 1, 0], [1, 0, 1, 1], [0, 0, 1, 0], [1, 1, 0, 0], [0, 1, 0, 0], [0, 1, 1, 1], [1, 1, 0, 1], [0, 0, 0, 1], [0, 1, 0, 1], [0, 0, 0, 0], [1, 1, 1, 1], [1, 0, 1, 0], [0, 0, 1, 1], [1, 0, 0, 1], [1, 0, 0, 0], [0, 1, 1, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [1, 0, 1, 1], [1, 0, 1, 0], [1, 1, 0, 1], [0, 1, 1, 1], [1, 0, 0, 0], [1, 1, 1, 1], [1, 0, 0, 1], [1, 1, 0, 0], [0, 1, 0, 1], [0, 1, 1, 0], [0, 0, 1, 1], [0, 0, 0, 0], [1, 1, 1, 0], [1, 0, 1, 1], [1, 0, 0, 0], [1, 1, 0, 0], [0, 1, 1, 1], [0, 0, 0, 1], [1, 1, 1, 0], [0, 0, 1, 0], [1, 1, 0, 1], [0, 1, 1, 0], [1, 1, 1, 1], [0, 0, 0, 0], [1, 0, 0, 1], [1, 0, 1, 0], [0, 1, 0, 0], [0, 1, 0, 1], [0, 0, 1, 1]],
          [[1, 1, 0, 0], [0, 0, 0, 1], [1, 0, 1, 0], [1, 1, 1, 1], [1, 0, 0, 1], [0, 0, 1, 0], [0, 1, 1, 0], [1, 0, 0, 0], [0, 0, 0, 0], [1, 1, 0, 1], [0, 0, 1, 1], [0, 1, 0, 0], [1, 1, 1, 0], [0, 1, 1, 1], [0, 1, 0, 1], [1, 0, 1, 1], [1, 0, 1, 0], [1, 1, 1, 1], [0, 1, 0, 0], [0, 0, 1, 0], [0, 1, 1, 1], [1, 1, 0, 0], [1, 0, 0, 1], [0, 1, 0, 1], [0, 1, 1, 0], [0, 0, 0, 1], [1, 1, 0, 1], [1, 1, 1, 0], [0, 0, 0, 0], [1, 0, 1, 1], [0, 0, 1, 1], [1, 0, 0, 0], [1, 0, 0, 1], [1, 1, 1, 0], [1, 1, 1, 1], [0, 1, 0, 1], [0, 0, 1, 0], [1, 0, 0, 0], [1, 1, 0, 0], [0, 0, 1, 1], [0, 1, 1, 1], [0, 0, 0, 0], [0, 1, 0, 0], [1, 0, 1, 0], [0, 0, 0, 1], [1, 1, 0, 1], [1, 0, 1, 1], [0, 1, 1, 0], [0, 1, 0, 0], [0, 0, 1, 1], [0, 0, 1, 0], [1, 1, 0, 0], [1, 0, 0, 1], [0, 1, 0, 1], [1, 1, 1, 1], [1, 0, 1, 0], [1, 0, 1, 1], [1, 1, 1, 0], [0, 0, 0, 1], [0, 1, 1, 1], [0, 1, 1, 0], [0, 0, 0, 0], [1, 0, 0, 0], [1, 1, 0, 1]],
          [[0, 1, 0, 0], [1, 0, 1, 1], [0, 0, 1, 0], [1, 1, 1, 0], [1, 1, 1, 1], [0, 0, 0, 0], [1, 0, 0, 0], [1, 1, 0, 1], [0, 0, 1, 1], [1, 1, 0, 0], [1, 0, 0, 1], [0, 1, 1, 1], [0, 1, 0, 1], [1, 0, 1, 0], [0, 1, 1, 0], [0, 0, 0, 1], [1, 1, 0, 1], [0, 0, 0, 0], [1, 0, 1, 1], [0, 1, 1, 1], [0, 1, 0, 0], [1, 0, 0, 1], [0, 0, 0, 1], [1, 0, 1, 0], [1, 1, 1, 0], [0, 0, 1, 1], [0, 1, 0, 1], [1, 1, 0, 0], [0, 0, 1, 0], [1, 1, 1, 1], [1, 0, 0, 0], [0, 1, 1, 0], [0, 0, 0, 1], [0, 1, 0, 0], [1, 0, 1, 1], [1, 1, 0, 1], [1, 1, 0, 0], [0, 0, 1, 1], [0, 1, 1, 1], [1, 1, 1, 0], [1, 0, 1, 0], [1, 1, 1, 1], [0, 1, 1, 0], [1, 0, 0, 0], [0, 0, 0, 0], [0, 1, 0, 1], [1, 0, 0, 1], [0, 0, 1, 0], [0, 1, 1, 0], [1, 0, 1, 1], [1, 1, 0, 1], [1, 0, 0, 0], [0, 0, 0, 1], [0, 1, 0, 0], [1, 0, 1, 0], [0, 1, 1, 1], [1, 0, 0, 1], [0, 1, 0, 1], [0, 0, 0, 0], [1, 1, 1, 1], [1, 1, 1, 0], [0, 0, 1, 0], [0, 0, 1, 1], [1, 1, 0, 0]],
          [[1, 1, 0, 1], [0, 0, 1, 0], [1, 0, 0, 0], [0, 1, 0, 0], [0, 1, 1, 0], [1, 1, 1, 1], [1, 0, 1, 1], [0, 0, 0, 1], [1, 0, 1, 0], [1, 0, 0, 1], [0, 0, 1, 1], [1, 1, 1, 0], [0, 1, 0, 1], [0, 0, 0, 0], [1, 1, 0, 0], [0, 1, 1, 1], [0, 0, 0, 1], [1, 1, 1, 1], [1, 1, 0, 1], [1, 0, 0, 0], [1, 0, 1, 0], [0, 0, 1, 1], [0, 1, 1, 1], [0, 1, 0, 0], [1, 1, 0, 0], [0, 1, 0, 1], [0, 1, 1, 0], [1, 0, 1, 1], [0, 0, 0, 0], [1, 1, 1, 0], [1, 0, 0, 1], [0, 0, 1, 0], [0, 1, 1, 1], [1, 0, 1, 1], [0, 1, 0, 0], [0, 0, 0, 1], [1, 0, 0, 1], [1, 1, 0, 0], [1, 1, 1, 0], [0, 0, 1, 0], [0, 0, 0, 0], [0, 1, 1, 0], [1, 0, 1, 0], [1, 1, 0, 1], [1, 1, 1, 1], [0, 0, 1, 1], [0, 1, 0, 1], [1, 0, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [1, 1, 1, 0], [0, 1, 1, 1], [0, 1, 0, 0], [1, 0, 1, 0], [1, 0, 0, 0], [1, 1, 0, 1], [1, 1, 1, 1], [1, 1, 0, 0], [1, 0, 0, 1], [0, 0, 0, 0], [0, 0, 1, 1], [0, 1, 0, 1], [0, 1, 1, 0], [1, 0, 1, 1]]]

# 4 STRENGTH state tablosu @VA 0x10e2318/2350/2388/23c0 (her biri 56-byte bit-sliced C||D).
# KDF'te her round'da bunlardan biri expand edilip subkey uretir ve state DES-encrypt edilir.
STRENGTH = [[1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0],
            [1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0],
            [0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0]]


# ---------------------------------------------------------------------------
# DES PRIMITIVES (bit-sliced, IP/FP YOK) — FUN_006224d0 / FUN_00622820 birebir.
# ---------------------------------------------------------------------------

def _expand_key_schedule(state):
    """
    FUN_00622820 birebir.
    Girdi: 56+ elemanli bit-sliced state. state[0:28]=C, state[28:56]=D.
    Cikti: 16 x 48-elemanli bit-sliced subkey listesi.
    Her round: C ve D'yi shift[r] kadar SOLA dondur (28-bit), sonra PC-2 ile 48-bit subkey.
    DIKKAT: state KOPYALANIR (orijinal degismez), her round rotate KUMULATIF
    (donen state uzerinde devam eder) — disasm'daki in-place rotate ile ayni.
    """
    c = list(state[0:28])
    d = list(state[28:56])
    subkeys = []
    for r in range(16):
        for _ in range(SHIFT[r]):
            # 28-bit sola rotate: ilk eleman sona gider.
            c = c[1:] + c[0:1]
            d = d[1:] + d[0:1]
        cd = c + d                       # 56 bit
        sk = [cd[PC2[i] - 1] for i in range(48)]   # PC-2, 1-indeksli -> 0-indeksli
        subkeys.append(sk)
    return subkeys


def _des_block(data, subkeys, decrypt):
    """
    FUN_006224d0 birebir. 16-round Feistel, IP/FP YOK ve SON ROUND'DA SWAP YOK.
    data: 64-elemanli bit-sliced dizi (yerinde DEGISTIRILIR ve dondurulur).
          data[0:32]=L, data[32:64]=R.
    decrypt=True  -> subkey ters sira (round_idx = 15 - r). (param_3==0)
    decrypt=False -> subkey duz sira. (encrypt, KDF'te kullanilir)

    DIKKAT (disasm'dan): round 0..14 -> klasik Feistel swap
        (new_L = old_R ; new_R = old_L XOR P(f(R))).
    round 15 (son) -> SWAP YOK, sadece L'ye XOR:
        (L = old_L XOR P(f(R)) ; R degismez).
    Bu "son-swap-yok" yapisi sayesinde decrypt == ters-subkey'li encrypt (involution).
    """
    for r in range(16):
        kr = (15 - r) if decrypt else r
        sk = subkeys[kr]
        # f-fonksiyonu girisi: temp[i] = data[31 + E[i]] XOR subkey[i]   (R'nin E-expansion'i)
        temp = [data[31 + E_EXPANSION[i]] ^ sk[i] for i in range(48)]
        # 8 S-box, her biri 6 bit -> 4 bit (bit-sliced). row=t0,t5 ; col=t1,t2,t3,t4.
        sout = [0] * 32
        for g in range(8):
            b = g * 6
            t0, t1, t2, t3, t4, t5 = temp[b], temp[b + 1], temp[b + 2], temp[b + 3], temp[b + 4], temp[b + 5]
            idx = ((((((t0 * 2 | t5) * 2 | t1) * 2 | t2) * 2 | t3) * 2 | t4))
            nib = SBOXES[g][idx]         # 4-bit bit-sliced cikti
            sout[g * 4 + 0] = nib[0]
            sout[g * 4 + 1] = nib[1]
            sout[g * 4 + 2] = nib[2]
            sout[g * 4 + 3] = nib[3]
        # P-permutation: perm[j] = sout[P[j]-1]  ;  fout = old_L XOR perm
        fout = [data[i] ^ sout[P_PERM[i] - 1] for i in range(32)]
        if r < 15:
            # SWAP: new_L = old_R ; new_R = fout
            newL = data[32:64]
            data[0:32] = newL
            data[32:64] = fout
        else:
            # SON ROUND: swap YOK. L = fout ; R degismez.
            data[0:32] = fout
    return data


# ---------------------------------------------------------------------------
# KDF — gercek subkey turetme. FUN_006223a0 + FUN_00622430 birebir.
# ---------------------------------------------------------------------------

def _distribute_key_bytes(state, kptr):
    """
    FUN_00622430'un sadece dagitim kismi (DES cagrilari disarida).
    8 key byte'i state'e bit-XOR'lar (MSB-first, base = 2 + k*8). null byte kptr'i ilerletmez.
    state YERINDE degisir. Yeni kptr dondurur.
    """
    for k in range(8):
        b = KEY_STRING[kptr] if kptr < len(KEY_STRING) else 0
        if b != 0:
            kptr += 1
        base = 2 + k * 8
        # disasm: pbVar2[-2..+5] ^= bit7..bit0  (pbVar2 = state + base)
        state[base - 2] ^= (b >> 7) & 1
        state[base - 1] ^= (b >> 6) & 1
        state[base + 0] ^= (b >> 5) & 1
        state[base + 1] ^= (b >> 4) & 1
        state[base + 2] ^= (b >> 3) & 1
        state[base + 3] ^= (b >> 2) & 1
        state[base + 4] ^= (b >> 1) & 1
        state[base + 5] ^= (b >> 0) & 1
    return kptr


def derive_subkeys():
    """
    FUN_006223a0 birebir. 4-round KDF.
      state = zeros[64]
      kptr  = 0
      for i in 0..3:
        kptr = distribute(state, kptr)           # 8 key byte -> state
        sk_i = expand(STRENGTH[i])               # strengthening subkey
        state = des_encrypt(state, sk_i)         # state'i ileri DES-encrypt et
      real_subkeys = expand(state)
    Donen: gercek decrypt icin 16 subkey.
    """
    state = [0] * 64
    kptr = 0
    for i in range(4):
        kptr = _distribute_key_bytes(state, kptr)
        sk_i = _expand_key_schedule(STRENGTH[i])
        state = _des_block(state, sk_i, decrypt=False)   # ENCRYPT (duz subkey sira)
    return _expand_key_schedule(state)


# ---------------------------------------------------------------------------
# BYTE <-> BIT-SLICED donusumu (MSB-first).
# ---------------------------------------------------------------------------

def _bytes_to_bits(block8):
    """8 byte -> 64 bit, her byte MSB-first: bit[byte*8 + j] = (b >> (7-j)) & 1."""
    bits = [0] * 64
    for i in range(8):
        b = block8[i]
        base = i * 8
        bits[base + 0] = (b >> 7) & 1
        bits[base + 1] = (b >> 6) & 1
        bits[base + 2] = (b >> 5) & 1
        bits[base + 3] = (b >> 4) & 1
        bits[base + 4] = (b >> 3) & 1
        bits[base + 5] = (b >> 2) & 1
        bits[base + 6] = (b >> 1) & 1
        bits[base + 7] = (b >> 0) & 1
    return bits


def _bits_to_bytes(bits):
    """64 bit -> 8 byte, MSB-first (FUN_006221b0 cikti pack'i)."""
    out = bytearray(8)
    for i in range(8):
        base = i * 8
        v = 0
        for j in range(8):
            v = (v << 1) | bits[base + j]
        out[i] = v
    return out


# ---------------------------------------------------------------------------
# IKINCI KATMAN — LCG akis sifresi (FUN_004f8770 @VA 0x4f8770).
# DES decrypt CIKTISINA uygulanir. KO tablo loader'i her cagrida:
#   FUN_004f8770(ecx=data, edx=size, seed=0x418, mult=0x8041, inc=0x1804)
# Bu sabitler tum tablo loader cagri yerlerinde ayni (push 0x1804; push 0x8041; push 0x418).
#
# Asm (birebir):
#   key = seed (0x418)
#   for each byte c in data:
#     plain = ((key >> 8) ^ c) & 0xff
#     key   = ((c + key) & 0xffff) * mult + inc   ; &0xffff
#     data[i] = plain     (yerinde)
# DOGRULAMA: Unicorn ile 0x4f8770 ciktisina BIREBIR esit (a5 4e 00 01 ...).
LCG_SEED = 0x418
LCG_MULT = 0x8041
LCG_INC = 0x1804


def lcg_decrypt(data, seed=LCG_SEED, mult=LCG_MULT, inc=LCG_INC):
    """FUN_004f8770 birebir — DES ciktisina 2. katman akis-sifre cozumu."""
    out = bytearray(len(data))
    key = seed
    for i in range(len(data)):
        c = data[i]
        out[i] = ((key >> 8) ^ c) & 0xff
        key = (((c + key) & 0xffff) * mult + inc) & 0xffff
    return bytes(out)


def lcg_encrypt(data, seed=LCG_SEED, mult=LCG_MULT, inc=LCG_INC):
    """lcg_decrypt'in tam tersi — duz veriden akis-sifreli cikti uretir.
    key guncellemesi CIPHERTEXT byte'i (uretilen c) ile beslendigi icin
    lcg_decrypt(lcg_encrypt(x)) == x (ayni key dizisi cikar)."""
    out = bytearray(len(data))
    key = seed
    for i in range(len(data)):
        c = ((key >> 8) ^ data[i]) & 0xff     # ciphertext byte
        out[i] = c
        key = (((c + key) & 0xffff) * mult + inc) & 0xffff
    return bytes(out)


# ---------------------------------------------------------------------------
# MASTER DECRYPT — FUN_006221b0 birebir.
# ---------------------------------------------------------------------------

def decrypt_tbl(path):
    """
    .tbl dosyasini coz, decrypted_size'a truncate edilmis ham TABLO verisi (bytes) dondur.

    TAM BORU HATTI (FUN_006221b0 -> FUN_004f8770):
      1) MAGIC (ilk 16 byte) dogrula.
      2) decrypted_size = byteswap(LE u32 @[16:20]) = BE okuma.
         (Oyun bunu DAT_00f82708 = _byteswap_ulong ile cevirir; alan big-endian saklanmis.)
      3) payload = data[20:], uzunlugu 8'in kati olmali.
      4) DES katmani: her 8-byte blok ECB decrypt (subkey TERS sira), yerinde yaz.
      5) decrypted_size'a TRUNCATE et.
      6) LCG katmani: FUN_004f8770 akis-sifre cozumu (seed=0x418, mult=0x8041, inc=0x1804).
    Sonuc = ham tablo (genelde [rowCount:u32][kayit*]).
    """
    with open(path, "rb") as f:
        raw = f.read()

    if len(raw) < 20:
        raise ValueError("dosya cok kucuk (< 20 byte): %s" % path)
    if raw[:16] != MAGIC:
        raise ValueError("MAGIC eslesmiyor: %s" % path)

    # decrypted_size: alan big-endian saklanmis (oyun byteswap eder).
    dec_size = struct.unpack_from(">I", raw, 16)[0]
    payload = raw[20:]
    if len(payload) == 0 or (len(payload) % 8) != 0:
        raise ValueError("payload uzunlugu 8'in kati degil: %d (%s)" % (len(payload), path))

    subkeys = derive_subkeys()

    # --- Katman 1: DES decrypt (in-place, ECB) ---
    out = bytearray(len(payload))
    nblocks = len(payload) // 8
    for bi in range(nblocks):
        off = bi * 8
        bits = _bytes_to_bits(payload[off:off + 8])
        bits = _des_block(bits, subkeys, decrypt=True)
        out[off:off + 8] = _bits_to_bytes(bits)

    # --- Truncate ---
    if 0 < dec_size <= len(out):
        out = out[:dec_size]
    else:
        # bozuk/eksik size: tam payload uzerinde devam et (yine de LCG uygulanir)
        dec_size = len(out)

    # --- Katman 2: LCG akis-sifre cozumu ---
    return lcg_decrypt(bytes(out))


def encrypt_tbl(data):
    """
    Ham tablo verisini (decrypt_tbl'in verdigi format) tekrar sifreli .tbl
    dosya byte'larina cevir. decrypt_tbl'in TAM TERSI:
      1) LCG katmani: lcg_encrypt(data)  (uzunluk N = len(data))
      2) 8'in katina pad'le (DES blok hizasi). Pad byte'lari onemsiz — yuklemede
         dec_size'a truncate edilip atiliyor; sifir kullaniyoruz.
      3) DES katmani: her 8-byte blok ECB encrypt (subkey DUZ sira).
      4) Header: MAGIC(16) + decrypted_size(N, big-endian u32) + payload.
    Sonuc: oyunun decrypt_tbl'i geri cozunce AYNEN 'data'yi veren gecerli .tbl.
    """
    n = len(data)
    lcg = lcg_encrypt(data)

    # 8'in katina sifir-pad (DES blok hizasi)
    pad = (-n) % 8
    lcg_padded = lcg + b"\x00" * pad

    subkeys = derive_subkeys()

    # --- Katman: DES encrypt (in-place, ECB, DUZ subkey sira) ---
    payload = bytearray(len(lcg_padded))
    for bi in range(len(lcg_padded) // 8):
        off = bi * 8
        bits = _bytes_to_bits(lcg_padded[off:off + 8])
        bits = _des_block(bits, subkeys, decrypt=False)
        payload[off:off + 8] = _bits_to_bytes(bits)

    # --- Header: MAGIC + BE u32 dec_size + payload ---
    return MAGIC + struct.pack(">I", n) + bytes(payload)


# ---------------------------------------------------------------------------
# TABLO SEMASI — cozulmus mgame .tbl -> tipli kolonlar/satirlar.
# Kaynak: client tablo-okuyucu fonksiyonlari (FUN_004f8200 alan-okuyucu switch +
# FUN_004f8660 boyut switch) statik decompile'dan + 2000+ gercek tabloda pasif
# dogrulama (byte-byte tam-tuketim + okunabilir isimler).
#
# Cozulmus veri yerlesimi:
#   [0]  u32  magic/versiyon
#   [4]  u8   flag
#   [5]  u32  colCount            (HIZALANMAMIS — offset 5)
#   [9]  u32 x colCount  colTypes
#   ...  u32  rowCount            (colTypes'tan SONRA)
#   ...  satirlar (SIKI paketli, alanlar arasi padding YOK)
# ---------------------------------------------------------------------------

# tip kodu -> (isim, struct-format | "str", byte-genisligi)
TBL_TYPE_INFO = {
    1:  ("char",   "<b", 1),    # int8   — bu client'ta gozlenmedi (boyut kesin, sign tahmin)
    2:  ("byte",   "<B", 1),    # uint8  — dogrulandi
    3:  ("short",  "<h", 2),    # int16  — dogrulandi
    4:  ("word",   "<H", 2),    # uint16 — gozlenmedi (boyut kesin)
    5:  ("int",    "<i", 4),    # int32  — signed KANITLI (negatif stat-mod)
    6:  ("dword",  "<I", 4),    # uint32 — dogrulandi (ID'ler)
    7:  ("string", "str", None),  # u32 len + N byte
    8:  ("float",  "<f", 4),    # float32 — dogrulandi (0.5, 2.0...)
    9:  ("qword",  "<q", 8),    # 8-byte — gozlenmedi (int64 varsayilan; double olabilir)
    10: ("int64",  "<q", 8),    # int64  — KANITLI (double DEGIL)
}

TBL_STR_ENCODING = "cp1254"    # KO string'leri Turkce/latin cp1254


def parse_table(data):
    """
    Cozulmus (decrypt_tbl ciktisi) mgame .tbl byte'larini yapiya ayirir.
    Doner: dict{ magic, flag, col_types, rows, consumed, size }
      col_types = [tip_kodu, ...]
      rows      = [[tipli deger, ...], ...]
    consumed==size ise sema tam dogru (cursor tabloyu tam tuketti).
    """
    if len(data) < 9:
        raise ValueError("veri cok kisa (< 9 byte)")
    magic = struct.unpack_from("<I", data, 0)[0]
    flag = data[4]
    col_count = struct.unpack_from("<I", data, 5)[0]     # DIKKAT: hizalanmamis offset 5
    if not (0 < col_count < 4096):
        raise ValueError("colCount makul degil: %d" % col_count)
    col_types = [struct.unpack_from("<I", data, 9 + i * 4)[0] for i in range(col_count)]
    off = 9 + col_count * 4
    row_count = struct.unpack_from("<I", data, off)[0]
    off += 4

    rows = []
    for _ in range(row_count):
        row = []
        for t in col_types:
            info = TBL_TYPE_INFO.get(t)
            if info is None:
                raise ValueError("bilinmeyen kolon tipi: %d @off=%d" % (t, off))
            _name, fmt, width = info
            if fmt == "str":
                n = struct.unpack_from("<i", data, off)[0]
                off += 4
                if n < 0:
                    n = 0
                raw = data[off:off + n]
                off += n
                row.append(raw.decode(TBL_STR_ENCODING, "replace"))
            else:
                (v,) = struct.unpack_from(fmt, data, off)
                off += width
                row.append(v)
        rows.append(row)

    return {"magic": magic, "flag": flag, "col_types": col_types,
            "rows": rows, "consumed": off, "size": len(data)}


def serialize_table(parsed):
    """
    parse_table ciktisini (dict) tekrar cozulmus mgame .tbl byte'larina cevirir —
    parse_table'in TAM TERSI. serialize_table(parse_table(x)) == x olmali.
    CSV/duzenleme sonrasi string gelen sayisal alanlar otomatik int/float'a cevrilir.
    """
    col_types = parsed["col_types"]
    rows = parsed["rows"]
    out = bytearray()
    out += struct.pack("<I", parsed.get("magic", 0))
    out += struct.pack("<B", parsed.get("flag", 0) & 0xFF)
    out += struct.pack("<I", len(col_types))
    for t in col_types:
        out += struct.pack("<I", t)
    out += struct.pack("<I", len(rows))
    for row in rows:
        for t, v in zip(col_types, row):
            _name, fmt, _w = TBL_TYPE_INFO[t]
            if fmt == "str":
                b = v.encode(TBL_STR_ENCODING, "replace") if isinstance(v, str) else bytes(v)
                out += struct.pack("<i", len(b)) + b
            else:
                if isinstance(v, str):                      # CSV'den geldi -> sayiya cevir
                    v = float(v) if fmt == "<f" else int(v)
                out += struct.pack(fmt, v)
    return bytes(out)


# ---------------------------------------------------------------------------
# FORMAT B — bazi tablolar (MOB, MON yerine MOB; Quest_image_us, INDUN_SCHEDULE,
# cml, DisguiseRing, item_user_buy_noma_us) MAGIC/DES OLMADAN, sadece LCG ile
# sifreli + HIZALI baslik:
#   [u32 colCount][u32 type * colCount][u32 rowCount][rows]
# (Standart Format A ise: DES+LCG + MAGIC header + [u32][u8][u32 colCount@5]...).
# Format-B string'leri cp949 (Korece locale). Round-trip byte-exact dogrulandi.
# ---------------------------------------------------------------------------

TBL_STR_ENCODING_B = "cp949"


def parse_table_b(data):
    """Format-B (LCG-only, hizali baslik) tabloyu yapiya ayirir. parse_table ile ayni dict."""
    col_count = struct.unpack_from("<I", data, 0)[0]
    if not (0 < col_count < 256):
        raise ValueError("Format-B colCount makul degil: %d" % col_count)
    col_types = [struct.unpack_from("<I", data, 4 + i * 4)[0] for i in range(col_count)]
    off = 4 + col_count * 4
    row_count = struct.unpack_from("<I", data, off)[0]
    off += 4
    rows = []
    for _ in range(row_count):
        row = []
        for t in col_types:
            info = TBL_TYPE_INFO.get(t)
            if info is None:
                raise ValueError("bilinmeyen kolon tipi: %d @off=%d" % (t, off))
            _n, fmt, w = info
            if fmt == "str":
                n = struct.unpack_from("<i", data, off)[0]
                off += 4
                if n < 0:
                    n = 0
                row.append(data[off:off + n].decode(TBL_STR_ENCODING_B, "replace"))
                off += n
            else:
                (v,) = struct.unpack_from(fmt, data, off)
                off += w
                row.append(v)
        rows.append(row)
    return {"col_types": col_types, "rows": rows, "consumed": off, "size": len(data)}


def serialize_table_b(parsed):
    """parse_table_b'nin TERSI — Format-B ham (LCG oncesi) byte'lari uretir."""
    ct = parsed["col_types"]
    out = bytearray()
    out += struct.pack("<I", len(ct))
    for t in ct:
        out += struct.pack("<I", t)
    out += struct.pack("<I", len(parsed["rows"]))
    for row in parsed["rows"]:
        for t, v in zip(ct, row):
            _n, fmt, _w = TBL_TYPE_INFO[t]
            if fmt == "str":
                b = v.encode(TBL_STR_ENCODING_B, "replace") if isinstance(v, str) else bytes(v)
                out += struct.pack("<i", len(b)) + b
            else:
                if isinstance(v, str):
                    v = float(v) if fmt == "<f" else int(v)
                out += struct.pack(fmt, v)
    return bytes(out)


# ---------------------------------------------------------------------------
# BIRLESIK arayuz — format otomatik algila. GUI/CLI bunlari kullanir.
# ---------------------------------------------------------------------------

def load_tbl(path):
    """Bir .tbl'i format-bagimsiz yukle. Doner: parse dict + 'format' anahtari (A/B).
    Desteklenmeyen (ucuncu) formatta ValueError firlatir."""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:16] == MAGIC:                              # Format A: DES+LCG+MAGIC
        p = parse_table(decrypt_tbl(path))
        p["format"] = "A"
        return p
    # Format B dene: LCG-only + hizali baslik
    try:
        p = parse_table_b(lcg_decrypt(raw))
    except Exception:
        p = None
    if p is None or p["consumed"] != p["size"]:
        raise ValueError("desteklenmeyen .tbl formati — bilinen sifreleme (A: DES+LCG, "
                         "B: LCG) ile cozulemedi; farkli/ucuncu bir format")
    p["format"] = "B"
    return p


def save_tbl(parsed, path):
    """parse dict'i formatina gore (A/B) geri sifreleyip yazar."""
    if parsed.get("format") == "B":
        out = lcg_encrypt(serialize_table_b(parsed))
    else:
        out = encrypt_tbl(serialize_table(parsed))
    with open(path, "wb") as f:
        f.write(out)


# ---------------------------------------------------------------------------
# CSV export / import — insan-okunur duzenleme icin.
# Ilk satir "#TBL ..." meta (format/magic/flag/tipler); ardindan basliklar + veri.
# ---------------------------------------------------------------------------

def to_csv(parsed, out_path):
    """parse dict'ini CSV'ye yaz (kendini-tarifleyen: format+meta satiri + basliklar)."""
    import csv
    ct = parsed["col_types"]
    fmt = parsed.get("format", "A")
    if fmt == "B":
        meta = "#TBL format=B types=%s" % ",".join(str(t) for t in ct)
    else:
        meta = "#TBL format=A magic=%d flag=%d types=%s" % (
            parsed.get("magic", 0), parsed.get("flag", 0), ",".join(str(t) for t in ct))
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        f.write(meta + "\n")
        w = csv.writer(f)
        w.writerow(["col%d_%s" % (i, TBL_TYPE_INFO[t][0]) for i, t in enumerate(ct)])
        for row in parsed["rows"]:
            w.writerow(row)


def from_csv(csv_path):
    """to_csv ciktisini geri parse-uyumlu dict'e cevir (save_tbl icin, format dahil)."""
    import csv
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        first = f.readline().rstrip("\n")
        if not first.startswith("#TBL"):
            raise ValueError("CSV meta satiri (#TBL ...) yok — bu araçla uretilmis CSV degil")
        meta = {}
        for tok in first[4:].split():
            k, _, val = tok.partition("=")
            meta[k] = val
        fmt = meta.get("format", "A")
        col_types = [int(x) for x in meta["types"].split(",") if x != ""]
        r = csv.reader(f)
        next(r, None)                                       # baslik satirini atla
        rows = []
        for rec in r:
            if not rec:
                continue
            row = []
            for t, cell in zip(col_types, rec):
                _n, fld, _w = TBL_TYPE_INFO[t]
                if fld == "str":
                    row.append(cell)
                elif fld == "<f":
                    row.append(float(cell))
                else:
                    row.append(int(cell))
            rows.append(row)
    parsed = {"format": fmt, "col_types": col_types, "rows": rows}
    if fmt == "A":
        parsed["magic"] = int(meta.get("magic", "0"))
        parsed["flag"] = int(meta.get("flag", "0"))
    return parsed


def read_header_size(path):
    """Header'daki decrypted_size'i (byteswap/BE) dondurur — teshis icin."""
    with open(path, "rb") as f:
        head = f.read(20)
    return struct.unpack_from(">I", head, 16)[0]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _usage():
    print("KO .tbl araci — kullanim:")
    print("  python tbl.py info    <in.tbl>              dosya bilgisi (tipler, satir sayisi)")
    print("  python tbl.py csv     <in.tbl> [out.csv]    cozup CSV'ye aktar (goruntule/duzenle)")
    print("  python tbl.py build   <in.csv> <out.tbl>    CSV'den geri .tbl uret (repack)")
    print("  python tbl.py decrypt <in.tbl> <out.bin>    ham cozulmus veriyi kaydet")
    print("  python tbl.py encrypt <in.bin> <out.tbl>    ham veriyi geri sifrele")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    import os

    args = sys.argv[1:]
    if not args:
        _usage(); sys.exit(1)
    cmd = args[0].lower()

    try:
        if cmd == "info" and len(args) >= 2:
            p = load_tbl(args[1])
            print("dosya      :", args[1])
            print("format     :", p.get("format", "A"))
            print("colCount   :", len(p["col_types"]))
            print("colTypes   :", p["col_types"])
            print("  (adlar)  :", [TBL_TYPE_INFO[t][0] for t in p["col_types"]])
            print("rowCount   :", len(p["rows"]))
            print("tam-tuketim:", "EVET" if p["consumed"] == p["size"] else "HAYIR (sema uyusmadi)")
            if p["rows"]:
                print("ilk satir  :", p["rows"][0])

        elif cmd == "csv" and len(args) >= 2:
            out = args[2] if len(args) >= 3 else (os.path.splitext(args[1])[0] + ".csv")
            p = load_tbl(args[1])
            to_csv(p, out)
            print("yazildi: %s  (%d satir, %d kolon, format %s)" %
                  (out, len(p["rows"]), len(p["col_types"]), p.get("format", "A")))

        elif cmd == "build" and len(args) >= 3:
            p = from_csv(args[1])
            save_tbl(p, args[2])
            print("yazildi: %s  (%d satir, format %s)" %
                  (args[2], len(p["rows"]), p.get("format", "A")))

        elif cmd == "decrypt" and len(args) >= 3:
            with open(args[2], "wb") as f:
                f.write(decrypt_tbl(args[1]))
            print("yazildi:", args[2])

        elif cmd == "encrypt" and len(args) >= 3:
            with open(args[1], "rb") as f:
                raw = f.read()
            with open(args[2], "wb") as f:
                f.write(encrypt_tbl(raw))
            print("yazildi:", args[2])

        else:
            _usage(); sys.exit(1)
    except Exception as e:
        print("HATA:", e); sys.exit(1)
