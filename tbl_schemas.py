#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tbl_schemas.py — bilinen KO .tbl tablolari icin insan-okunur kolon adlari.

GUI/CLI bu adlari SADECE gercek kolon SAYISI buradaki liste uzunluguyla TAM
eslesirse kullanir (yanlis-build korumasi). Uyusmazsa isim GOSTERILMEZ, tipe
(dword/string...) donulur — boylece yanlis etiket asla cikmaz.

Anahtar = dosya adi, kucuk harf, uzantisiz (ornek: "warpinfo").
Sema kaynagi: mevcut bir client-tarafi tablo-okuyucu implementasyonu + gercek
oyun verisiyle capraz-dogrulama. "?" = kolon var ama anlami kesin degil.
"""

import os

SCHEMAS = {
    "warpinfo": ["ID", "İsim", "Min Seviye", "Max Seviye", "Resim Yolu", "Açıklama"],

    # --- ANA ITEM TABLOSU (41 kolon) — item_org_us / item_org_tk ---
    "item_org_us": ["Item ID", "Uzantı Dosya No", "İsim", "Açıklama", "Uzantı Aktif",
        "?", "İkon/Model ID", "İkon/Model ID2", "?", "?", "Tür (Kind)", "?",
        "Kuşanma Slotu", "Irk", "Sınıf", "Hasar", "Saldırı Hızı", "Menzil", "Ağırlık",
        "Dayanıklılık", "Fiyat", "?", "Defans", "Yığılabilir", "Efekt 1", "Efekt 2",
        "Min Seviye", "Max Seviye", "Pet mi", "?", "Gerekli STR", "Gerekli STA",
        "Gerekli DEX", "Gerekli INT", "Gerekli MP", "Satış Grubu", "Scroll Derecesi",
        "?", "?", "?", "?"],
    "item_org_tk": ["Item ID", "Uzantı Dosya No", "İsim", "Açıklama", "Uzantı Aktif",
        "?", "İkon/Model ID", "İkon/Model ID2", "?", "?", "Tür (Kind)", "?",
        "Kuşanma Slotu", "Irk", "Sınıf", "Hasar", "Saldırı Hızı", "Menzil", "Ağırlık",
        "Dayanıklılık", "Fiyat", "?", "Defans", "Yığılabilir", "Efekt 1", "Efekt 2",
        "Min Seviye", "Max Seviye", "Pet mi", "?", "Gerekli STR", "Gerekli STA",
        "Gerekli DEX", "Gerekli INT", "Gerekli MP", "Satış Grubu", "Scroll Derecesi",
        "?", "?", "?", "?"],

    # --- ITEM UZANTI/ENCHANT (56 kolon) — TUM Item_Ext_N dosyalari (prefix ile) ---
    "item_ext": ["Uzantı Kayıt ID", "İsim", "Item Base ID", "Açıklama", "?", "?",
        "?", "Tip", "Hasar", "Saldırı Aralığı %", "Saldırı Gücü Oranı",
        "Kaçınma Oranı", "Dayanıklılık", "Fiyat Çarpanı", "Defans", "Hançer Defans",
        "Jamadar Defans", "Kılıç Defans", "Gürz Defans", "Balta Defans", "Mızrak Defans",
        "Ok Defans", "Ateş Hasarı", "Buz Hasarı", "Şimşek Hasarı", "Zehir Hasarı",
        "HP Yenileme", "MP Hasarı", "MP Yenileme", "Fiz. Hasar Yansıtma", "?", "STR Bonus",
        "STA Bonus", "DEX Bonus", "INT Bonus", "Büyü Gücü Bonus", "HP Bonus", "MP Bonus",
        "Ateş Direnci", "Buz Direnci", "Şimşek Direnci", "Büyü Direnci", "Zehir Direnci",
        "Lanet Direnci", "?", "?", "?", "?", "?", "Gerekli STR", "Gerekli STA",
        "Gerekli DEX", "Gerekli INT", "Gerekli MP", "?", "?"],

    # --- SKILL/BUYU ANA TABLO (38 kolon) — skill_magic_main_us / _tk ---
    "skill_magic_main_us": ["Skill ID", "Kod Adı", "İsim", "Açıklama", "Kendi Animasyon",
        "?", "?", "Kendi Efekt 1", "Efekt Parça 1", "Kendi Efekt 2", "Efekt Parça 2",
        "Uçan Efekt (mermi)", "?", "?", "Hedef Tipi", "Skill Puanı", "Sınıf", "Mana",
        "?", "?", "Tekrar Cast Süresi", "Gerekli Item", "Cast Süresi", "Bekleme (Cooldown)",
        "?", "?", "?", "?", "Tip 1 (alt-tablo)", "Tip 2", "Menzil", "?", "?", "?",
        "Gerekli/Önceki Skill", "?", "?", "?"],
    "skill_magic_main_tk": ["Skill ID", "Kod Adı", "İsim", "Açıklama", "Kendi Animasyon",
        "?", "?", "Kendi Efekt 1", "Efekt Parça 1", "Kendi Efekt 2", "Efekt Parça 2",
        "Uçan Efekt (mermi)", "?", "?", "Hedef Tipi", "Skill Puanı", "Sınıf", "Mana",
        "?", "?", "Tekrar Cast Süresi", "Gerekli Item", "Cast Süresi", "Bekleme (Cooldown)",
        "?", "?", "?", "?", "Tip 1 (alt-tablo)", "Tip 2", "Menzil", "?", "?", "?",
        "Gerekli/Önceki Skill", "?", "?", "?"],

    # --- NPC ISIM TABLOSU (7 kolon) ---
    "npc_us":   ["NPC ID", "İsim", "Proto/Tip ID", "?", "?", "?", "?"],
    "npc":      ["NPC ID", "İsim", "Proto/Tip ID", "?", "?", "?", "?"],
    "npc_tk":   ["NPC ID", "İsim", "Proto/Tip ID", "?", "?", "?", "?"],
    "k_npc_us": ["NPC ID", "İsim", "Proto/Tip ID", "?", "?", "?", "?"],
    "k_npc_tk": ["NPC ID", "İsim", "Proto/Tip ID", "?", "?", "?", "?"],

    # --- MOB ISIM TABLOSU ---
    "mob_us": ["Mob ID", "İsim", "Proto/Model ID", "Rütbe/Boss", "?", "?"],
    "mob_tk": ["Mob ID", "İsim", "Proto/Model ID", "Rütbe/Boss", "?", "?"],
    "mob":    ["Mob ID", "İsim (KR)", "Proto/Model ID", "?"],   # MOB.tbl, Format-B, 4 kolon

    # --- NPC/MOB HARITA KONUM (10 kolon) ---
    "npcmopmap_info_us": ["Kayıt ID", "NPC ID", "Bölge (Zone)", "?", "X", "Y",
        "İsim", "Tip", "?", "Açıklama"],
    "npcmopmap_info_tk": ["Kayıt ID", "NPC ID", "Bölge (Zone)", "?", "X", "Y",
        "İsim", "Tip", "?", "Açıklama"],
    "npcmopmap_info": ["Kayıt ID", "NPC ID", "Bölge (Zone)", "?", "X", "Y",
        "İsim", "Tip", "?", "Açıklama"],

    # --- NPC SATIS LISTESI (26 kolon) — [2..25]=24 item slotu ---
    "itemsell_table": ["Satış Grubu", "?"] + ["Item %d" % i for i in range(1, 25)],
    "itesell_table":  ["Satış Grubu", "?"] + ["Item %d" % i for i in range(1, 25)],

    # --- ITEM TAKAS/DONUSUM (27 kolon) — 5 giris + 5 cikis cifti ---
    "item_exchange": ["Exchange ID", "Tip", "?",
        "Kaynak Item 1", "Adet 1", "Kaynak Item 2", "Adet 2", "Kaynak Item 3", "Adet 3",
        "Kaynak Item 4", "Adet 4", "Kaynak Item 5", "Adet 5",
        "Sonuç Item 1", "Adet 1", "Sonuç Item 2", "Adet 2", "Sonuç Item 3", "Adet 3",
        "Sonuç Item 4", "Adet 4", "Sonuç Item 5", "Adet 5", "?", "?", "?", "?"],
    "item_exchange_us": ["Exchange ID", "Tip", "?",
        "Kaynak Item 1", "Adet 1", "Kaynak Item 2", "Adet 2", "Kaynak Item 3", "Adet 3",
        "Kaynak Item 4", "Adet 4", "Kaynak Item 5", "Adet 5",
        "Sonuç Item 1", "Adet 1", "Sonuç Item 2", "Adet 2", "Sonuç Item 3", "Adet 3",
        "Sonuç Item 4", "Adet 4", "Sonuç Item 5", "Adet 5", "?", "?", "?", "?"],

    # --- BASIT / BARIZ TABLOLAR ---
    "player_experience": ["Seviye", "Gerekli EXP"],
    "caption_us":        ["ID", "Altyazı Metni", "Başlangıç (sn)", "Bitiş (sn)"],
    "quest_image_us":    ["ID", "Resim Yolu"],
    "quest_image":       ["ID", "Resim Yolu"],
    "wing":              ["Item ID", "Model Yolu", "?", "?"],
    "indun_schedule_us": ["ID", "Etkinlik Adı", "?"],
    "indun_schedule":    ["ID", "Etkinlik Adı"],       # base varyant 2 kolon
}


def _lookup(key):
    """Anahtar -> kolon-adi listesi (sayi kontrolu yapmadan). Bilinmiyorsa None."""
    if key in SCHEMAS:
        return SCHEMAS[key]
    if key.startswith("item_ext_"):          # tum Item_Ext_N[_us/_tk] -> ortak sema
        return SCHEMAS.get("item_ext")
    return None


def column_names(table_filename, col_count):
    """table_filename ('warpinfo.tbl') + gercek col_count icin kolon adlari listesi
    dondur. Tablo bilinmiyorsa VEYA kolon sayisi tutmuyorsa None (isim gosterme)."""
    key = os.path.splitext(os.path.basename(table_filename))[0].lower()
    names = _lookup(key)
    if names and len(names) == col_count:
        return names
    return None
