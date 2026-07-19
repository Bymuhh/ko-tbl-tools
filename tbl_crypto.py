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


def read_header_size(path):
    """Header'daki decrypted_size'i (byteswap/BE) dondurur — teshis icin."""
    with open(path, "rb") as f:
        head = f.read(20)
    return struct.unpack_from(">I", head, 16)[0]


# ---------------------------------------------------------------------------
# TBL SEMA / KAYIT COZUCU (decrypt sonrasi)
# ---------------------------------------------------------------------------
# Cozulmus tablo (mgame TBL) yapisi:
#   [u32 ?][u8 ?][u32 colCount][u32 colType * colCount][rows...]
# Kolon tip kodlari degisken-uzunluk; string kolonlar (genelde 5/6/7 koduyla) u32-len + bytes.
# NOT: bu sunucudaki tam tip->okuyucu eslemesi tam dogrulanmadi; bu yuzden kayit
#      cozumu SEZGISEL (u32 kucuk + ardindan printable => string, aksi => int).

def _scan_u32(data, value):
    """Cozulmus tabloda bir u32 degerin (LE) tum offsetlerini dondurur."""
    patt = struct.pack("<I", value)
    res = []
    i = data.find(patt)
    while i >= 0:
        res.append(i)
        i = data.find(patt, i + 1)
    return res


def _heuristic_record(data, start, max_cols=48):
    """start'tan itibaren bir kaydi sezgisel coz (int/string ayrimi)."""
    pos = start
    cols = []
    for _ in range(max_cols):
        if pos + 4 > len(data):
            break
        v = struct.unpack_from("<I", data, pos)[0]
        if 0 <= v <= 300 and pos + 4 + v <= len(data):
            s = data[pos + 4:pos + 4 + v]
            printable = sum(1 for b in s if 32 <= b < 127)
            if v == 0 or printable >= max(1, int(v * 0.6)):
                cols.append(("str", s)); pos += 4 + v; continue
        cols.append(("int", v)); pos += 4
    return cols


# ---------------------------------------------------------------------------
# TEST / CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import traceback

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    try:
        default = os.path.normpath(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..",
                "Data",
                "Skill_Magic_1.tbl",
            )
        )
        path = sys.argv[1] if len(sys.argv) > 1 else default

        if not os.path.exists(path):
            print("[!] dosya yok:", path)
        else:
            print("[*] decrypt:", path)
            raw_len = os.path.getsize(path)
            hdr_size = read_header_size(path)
            print("    dosya boyutu :", raw_len)
            print("    header dec_sz :", hdr_size, "(0x%X)" % hdr_size)

            data = decrypt_tbl(path)
            print("    cozulmus boyut:", len(data))
            print("    ilk 40 byte  :", data[:40].hex(" "))

            # TBL sema: [u32 ?][u8 ?][u32 colCount][u32 colType*]
            if len(data) >= 13:
                col_count = struct.unpack_from("<I", data, 5)[0]
                if 0 < col_count < 256 and 9 + col_count * 4 <= len(data):
                    types = [
                        struct.unpack_from("<I", data, 9 + k * 4)[0]
                        for k in range(col_count)
                    ]
                    data_start = 9 + col_count * 4
                    print("    colCount     :", col_count)
                    print("    colTypes     :", types)
                    print("    data offset  :", data_start)
                    rec0 = _heuristic_record(data, data_start)
                    print("    --- ilk kayit (sezgisel) ---")
                    for i, (k, v) in enumerate(rec0[:24]):
                        if k == "str":
                            print("      col%-2d STR[%d] = %r" % (i, len(v), v))
                        else:
                            print("      col%-2d INT    = %d (0x%X)" % (i, v, v))
                else:
                    print(
                        "    (sema cozulemedi — basit tablo olabilir; ilk u32 = %d)"
                        % struct.unpack_from("<I", data, 0)[0]
                    )

            # Argumanla skill/item ID ara: python tbl_crypto.py <dosya> <id>
            if len(sys.argv) > 2:
                try:
                    sid = int(sys.argv[2], 0)
                    offs = _scan_u32(data, sid)
                    print(
                        "    [ara] %d (0x%X) -> %d konum: %s"
                        % (sid, sid, len(offs), offs[:8])
                    )
                    for o in offs[:3]:
                        print(
                            "      @%d baglam: %s"
                            % (o, data[max(0, o - 4) : o + 32].hex(" "))
                        )
                except ValueError:
                    pass
    except Exception:
        traceback.print_exc()

    try:
        input("\nKapatmak icin Enter'a bas...")
    except EOFError:
        pass
