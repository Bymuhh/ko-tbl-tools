#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tbl_editor.py — Knight Online .tbl görsel editörü (Tkinter, bağımlılıksız).

Çift tıkla aç (TBL-Editoru.bat) ya da `python tbl_editor.py`.
  1) "TBL Aç" → bir .tbl seç (otomatik çözülür, tabloya dolar)
  2) Hücreye çift tıkla → değeri düzenle → Enter
  3) "Kaydet" → yeni .tbl oluşur (geri şifrelenir)

Motor: tbl.py (aynı klasörde). Format A (DES+LCG) ve B (LCG) otomatik algılanır.
Kolon adları: tbl_schemas.py (bilinen tablolar için "Alış Fiyatı" vb.).
"""

import os
import sys
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tbl
import tbl_schemas

# --- Renk paleti (açık, modern) ------------------------------------------
BG        = "#eef1f8"     # ana zemin
APPBAR    = "#2d3561"     # üst bar (koyu indigo)
APPBAR_FG = "#ffffff"
CARD      = "#ffffff"
ROW_EVEN  = "#ffffff"
ROW_ODD   = "#f5f7fc"
HEAD_BG   = "#e7ecf7"
HEAD_FG   = "#2d3561"
SEL_BG    = "#3d7eff"
STATUS_BG = "#dfe4f0"
STATUS_FG = "#3a4054"
MUTED     = "#8a90a2"

BTN = {  # (normal, hover)
    "green":  ("#2f9e44", "#268038"),
    "blue":   ("#3d7eff", "#2a63d8"),
    "purple": ("#7048e8", "#5a37c4"),
    "red":    ("#e8590c", "#c44a08"),
    "gray":   ("#5c6377", "#474d5e"),
}


class TblEditor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("KO TBL Editörü")
        self.geometry("1120x680")
        self.minsize(760, 440)
        self.configure(bg=BG)

        self.parsed = None
        self.path = None
        self._edit_widget = None
        self._busy = False
        self._filter_job = None

        self._build_style()
        self._build_appbar()
        self._build_toolbar()
        self._build_table()
        self._build_statusbar()
        self._set_status("Hazır — bir .tbl açmak için “TBL Aç”a bas.")

    # ---- stil -------------------------------------------------------------
    def _build_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Treeview", rowheight=26, font=("Consolas", 10),
                     background=CARD, fieldbackground=CARD, borderwidth=0)
        st.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"),
                     background=HEAD_BG, foreground=HEAD_FG, relief="flat", padding=6)
        st.map("Treeview.Heading", background=[("active", "#dbe3f4")])
        st.map("Treeview", background=[("selected", SEL_BG)],
               foreground=[("selected", "#ffffff")])
        st.configure("Vertical.TScrollbar", background="#c9d0e0", troughcolor=BG,
                     borderwidth=0, arrowcolor=APPBAR)
        st.configure("Horizontal.TScrollbar", background="#c9d0e0", troughcolor=BG,
                     borderwidth=0, arrowcolor=APPBAR)

    def _mkbtn(self, parent, text, cmd, color):
        base, hov = BTN[color]
        b = tk.Label(parent, text=text, bg=base, fg="white", padx=14, pady=7,
                     font=("Segoe UI", 9, "bold"), cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.config(bg=hov))
        b.bind("<Leave>", lambda e: b.config(bg=base))
        return b

    # ---- app bar ----------------------------------------------------------
    def _build_appbar(self):
        bar = tk.Frame(self, bg=APPBAR, height=54)
        bar.pack(side="top", fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text="⚔  KO TBL Editörü", bg=APPBAR, fg=APPBAR_FG,
                 font=("Segoe UI Semibold", 15)).pack(side="left", padx=18)
        self.info_lbl = tk.Label(bar, text="dosya açık değil", bg=APPBAR,
                                 fg="#b9c0dd", font=("Segoe UI", 10))
        self.info_lbl.pack(side="right", padx=18)

    # ---- toolbar ----------------------------------------------------------
    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG, pady=9, padx=12)
        bar.pack(side="top", fill="x")

        for text, cmd, col in [
            ("📂  TBL Aç", self.open_file, "green"),
            ("💾  Kaydet", self.save, "blue"),
            ("💾  Farklı Kaydet", self.save_as, "blue"),
        ]:
            self._mkbtn(bar, text, cmd, col).pack(side="left", padx=(0, 7))

        tk.Frame(bar, width=1, height=26, bg="#c9d0e0").pack(side="left", padx=8)
        for text, cmd, col in [
            ("➕  Satır Ekle", self.add_row, "purple"),
            ("🗑  Satır Sil", self.del_row, "red"),
        ]:
            self._mkbtn(bar, text, cmd, col).pack(side="left", padx=(0, 7))

        # sağda arama/filtre
        box = tk.Frame(bar, bg=CARD, highlightbackground="#c9d0e0",
                       highlightthickness=1)
        box.pack(side="right")
        tk.Label(box, text="🔍", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 10)).pack(side="left", padx=(8, 2))
        self.filter_var = tk.StringVar()
        e = tk.Entry(box, textvariable=self.filter_var, width=26, relief="flat",
                     bg=CARD, font=("Segoe UI", 10), fg="#2d3561")
        e.pack(side="left", padx=(0, 8), pady=4, ipady=2)
        e.bind("<KeyRelease>", self._on_filter)
        self._filter_entry = e

    # ---- tablo ------------------------------------------------------------
    def _build_table(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(side="top", fill="both", expand=True, padx=12, pady=(2, 8))
        card = tk.Frame(wrap, bg=CARD, highlightbackground="#d3d9e8",
                        highlightthickness=1)
        card.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(card, show="headings", selectmode="browse")
        ysb = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(card, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        card.rowconfigure(0, weight=1)
        card.columnconfigure(0, weight=1)

        self.tree.tag_configure("odd", background=ROW_ODD)
        self.tree.tag_configure("even", background=ROW_EVEN)
        self.tree.bind("<Double-1>", self._on_double_click)

    # ---- durum çubuğu -----------------------------------------------------
    def _build_statusbar(self):
        self.status = tk.Label(self, text="", bg=STATUS_BG, fg=STATUS_FG, anchor="w",
                               font=("Segoe UI", 9), padx=14, pady=5)
        self.status.pack(side="bottom", fill="x")

    def _set_status(self, msg):
        self.status.config(text=msg)
        self.update_idletasks()

    def _set_info(self):
        if not self.parsed:
            self.info_lbl.config(text="dosya açık değil")
            return
        p = self.parsed
        full = "tam" if p["consumed"] == p["size"] else "EKSİK!"
        self.info_lbl.config(text="%s   ·   %d satır · %d kolon · format %s · %s" % (
            os.path.basename(self.path or ""), len(p["rows"]), len(p["col_types"]),
            p.get("format", "A"), full))

    # ---- arka-plan iş (thread-safe: Tk çağrıları hep ana-thread'de) -------
    def _run_bg(self, fn, on_done, on_err):
        q = queue.Queue()

        def work():
            try:
                q.put(("ok", fn()))
            except Exception as e:
                q.put(("err", e))

        threading.Thread(target=work, daemon=True).start()

        def poll():
            try:
                kind, val = q.get_nowait()
            except queue.Empty:
                self.after(40, poll)
                return
            (on_done if kind == "ok" else on_err)(val)

        self.after(40, poll)

    # ---- dosya aç ---------------------------------------------------------
    def open_file(self):
        if self._busy:
            return
        p = filedialog.askopenfilename(
            title="Bir .tbl dosyası seç",
            initialdir="C:/NTTGame/KnightOnlineEn/Data",
            filetypes=[("KO tablo", "*.tbl"), ("Tüm dosyalar", "*.*")])
        if p:
            self._open_path(p)

    def _open_path(self, p):
        if self._busy:
            return
        self._busy = True
        self._set_status("Çözülüyor: %s ..." % os.path.basename(p))
        self._run_bg(lambda: tbl.load_tbl(p),
                     lambda parsed: self._loaded(p, parsed),
                     self._load_err)

    def _load_err(self, e):
        self._busy = False
        self._set_status("Hata: %s" % e)
        messagebox.showerror("Açılamadı", str(e))

    def _loaded(self, path, parsed):
        self.path = path
        self.parsed = parsed
        self.filter_var.set("")
        self._populate()
        self._busy = False
        self._set_info()
        self.title("KO TBL Editörü — %s" % os.path.basename(path))
        self._set_status("Açıldı: %s   ·   hücreye çift tıkla = düzenle" % path)

    def _populate(self):
        self._destroy_editor()
        ct = self.parsed["col_types"]
        schema = tbl_schemas.column_names(self.path or "", len(ct)) if self.path else None
        cols = ["c%d" % i for i in range(len(ct))]
        self.tree["columns"] = cols
        for i, t in enumerate(ct):
            tname = tbl.TBL_TYPE_INFO.get(t, ("?",))[0]
            if schema:
                head, wide = schema[i], (tname == "string" or len(schema[i]) > 9)
            else:
                head, wide = "%d · %s" % (i, tname), (tname == "string")
            self.tree.heading(cols[i], text=head, anchor="w")
            self.tree.column(cols[i], width=(210 if wide else 95), anchor="w", stretch=False)
        self._apply_filter()

    def _apply_filter(self):
        """Filtreye uyan satırları göster (orijinal satır indeksi = iid, düzenleme
        her zaman tam veri modeline gider)."""
        self._destroy_editor()
        self.tree.delete(*self.tree.get_children())
        if not self.parsed:
            return
        q = self.filter_var.get().strip().lower()
        shown = 0
        for ri, row in enumerate(self.parsed["rows"]):
            if q and q not in " ".join(str(v).lower() for v in row):
                continue
            tag = "odd" if shown % 2 else "even"
            self.tree.insert("", "end", iid=str(ri),
                             values=[v for v in row], tags=(tag,))
            shown += 1
        if q:
            self._set_status("Filtre “%s” → %d / %d satır" %
                             (self.filter_var.get(), shown, len(self.parsed["rows"])))

    def _on_filter(self, _evt=None):
        if self._filter_job:
            self.after_cancel(self._filter_job)
        self._filter_job = self.after(220, self._apply_filter)

    # ---- hücre düzenleme --------------------------------------------------
    def _on_double_click(self, event):
        if self.parsed is None:
            return
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        col = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if not row_id or not col:
            return
        col_idx = int(col[1:]) - 1
        bbox = self.tree.bbox(row_id, col)
        if not bbox:
            return
        x, y, w, h = bbox
        cur = self.tree.set(row_id, self.tree["columns"][col_idx])
        self._destroy_editor()
        e = tk.Entry(self.tree, font=("Consolas", 10), relief="flat",
                     bg="#fff8dc", highlightthickness=2, highlightcolor=SEL_BG)
        e.place(x=x, y=y, width=w, height=h)
        e.insert(0, cur)
        e.select_range(0, "end")
        e.focus_set()
        e.bind("<Return>", lambda ev: self._commit(row_id, col_idx))
        e.bind("<Escape>", lambda ev: self._destroy_editor())
        e.bind("<FocusOut>", lambda ev: self._commit(row_id, col_idx))
        self._edit_widget = e

    def _commit(self, row_id, col_idx):
        if self._edit_widget is None:
            return
        new = self._edit_widget.get()
        t = self.parsed["col_types"][col_idx]
        name, fmt, _w = tbl.TBL_TYPE_INFO[t]
        if fmt != "str":
            try:
                val = float(new) if fmt == "<f" else int(new, 0)
            except ValueError:
                messagebox.showwarning("Geçersiz değer",
                    "Bu kolon “%s” (sayısal). “%s” bir sayı değil." % (name, new))
                try:
                    self._edit_widget.focus_set()
                except tk.TclError:
                    pass
                return
        else:
            val = new
        self.parsed["rows"][int(row_id)][col_idx] = val
        self.tree.set(row_id, self.tree["columns"][col_idx], val)
        self._destroy_editor()

    def _destroy_editor(self):
        if self._edit_widget is not None:
            try:
                self._edit_widget.destroy()
            except tk.TclError:
                pass
            self._edit_widget = None

    # ---- satır ekle / sil -------------------------------------------------
    def add_row(self):
        if self.parsed is None:
            return
        blank = []
        for t in self.parsed["col_types"]:
            _n, fmt, _w = tbl.TBL_TYPE_INFO[t]
            blank.append("" if fmt == "str" else (0.0 if fmt == "<f" else 0))
        self.parsed["rows"].append(blank)
        self.filter_var.set("")
        self._apply_filter()
        kids = self.tree.get_children()
        if kids:
            self.tree.see(kids[-1]); self.tree.selection_set(kids[-1])
        self._set_info()
        self._set_status("Yeni satır eklendi (en altta).")

    def del_row(self):
        if self.parsed is None:
            return
        sel = self.tree.selection()
        if not sel:
            self._set_status("Önce silmek istediğin satırı seç.")
            return
        del self.parsed["rows"][int(sel[0])]
        self._apply_filter()
        self._set_info()
        self._set_status("Satır silindi.")

    # ---- kaydet -----------------------------------------------------------
    def save(self):
        if self.path:
            self._save_to(self.path)
        else:
            self.save_as()

    def save_as(self):
        if self.parsed is None:
            return
        init = os.path.basename(self.path) if self.path else "yeni.tbl"
        out = filedialog.asksaveasfilename(
            title="Yeni .tbl olarak kaydet", defaultextension=".tbl",
            initialfile=init, filetypes=[("KO tablo", "*.tbl")])
        if out:
            self._save_to(out)

    def _save_to(self, out):
        if self._busy or self.parsed is None:
            return
        self._destroy_editor()
        self._busy = True
        self._set_status("Şifrelenip kaydediliyor: %s ..." % os.path.basename(out))

        def do():
            tbl.save_tbl(self.parsed, out)
            return out

        self._run_bg(do, self._saved, self._save_err)

    def _saved(self, out):
        self._busy = False
        self.path = out
        self.title("KO TBL Editörü — %s" % os.path.basename(out))
        self._set_info()
        self._set_status("Kaydedildi: %s" % out)
        messagebox.showinfo("Kaydedildi", "Yeni .tbl hazır:\n\n%s" % out)

    def _save_err(self, e):
        self._busy = False
        self._set_status("Kaydetme hatası: %s" % e)
        messagebox.showerror("Kaydedilemedi", str(e))


if __name__ == "__main__":
    app = TblEditor()
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        app.after(150, lambda: app._open_path(sys.argv[1]))
    app.mainloop()
