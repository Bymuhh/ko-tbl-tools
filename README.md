# ko-tbl-editor

A small GUI editor for the encrypted `.tbl` data files in a Knight Online client
— the tables that hold items, skills, NPCs, monsters, warps and so on. Open a
`.tbl`, edit the values in a grid, save it back out as a working `.tbl`.

Pure Python 3, standard library only (the GUI is Tkinter, which ships with
Python), so there is nothing to `pip install`.

![what it does](https://img.shields.io/badge/tables-251%2F254%20byte--exact-2f9e44)

## What it does

- **Opens and decrypts `.tbl` files.** KO ships its static data encrypted in two
  on-disk formats and the editor auto-detects both:
  - *Format A* — a modified DES (initial/final permutations removed, no swap on
    the last round) followed by a small 16-bit LCG stream cipher, behind a
    16-byte magic + size header. This is ~96% of the tables.
  - *Format B* — the LCG stream cipher only, no DES/header, with a slightly
    different table header. A handful of tables use it.
- **Shows the table as an editable grid.** Double-click a cell to change it;
  numeric columns are validated on commit. There's a search box to filter rows
  and buttons to add / delete rows.
- **Names the columns.** For known tables the headers read *Name / Damage /
  Price / Defense / Min Level* instead of raw types (`tbl_schemas.py`). Names are
  only shown when the column count matches the known schema, so a differently
  built client is never mislabeled — it just falls back to the type names.
- **Saves a real `.tbl`.** On save it re-serializes and re-encrypts in the same
  format it opened. Across the 254 tables I tested, 251 round-trip **byte-for-byte**
  (edit nothing → save → identical file), so nothing is lost or corrupted. The
  other 3 use a third encryption I haven't cracked, and are refused cleanly.

## Running it

Double-click **`TBL-Editoru.bat`** (Windows — launches without a console window).

Or from a terminal:

```
python tbl_editor.py                 # empty, then use "TBL Aç"
python tbl_editor.py Item_org_us.tbl # open a file directly
```

The open dialog starts in `C:\NTTGame\KnightOnlineEn\Data` by default; point it
wherever your client keeps its `Data` folder.

## The engine (`tbl.py`)

`tbl.py` is the crypto + parser the editor is built on, and it doubles as a CLI
if you'd rather batch things:

```
python tbl.py info  Item_org_us.tbl            # format, column types, row count
python tbl.py csv   Item_org_us.tbl out.csv    # decrypt + export to CSV
python tbl.py build out.csv new.tbl            # CSV -> .tbl (repack)
```

Or in code:

```python
import tbl
p = tbl.load_tbl("Npc_us.tbl")     # {"format", "col_types", "rows", ...}
p["rows"][0][1] = "New Name"
tbl.save_tbl(p, "Npc_us_edited.tbl")
```

## Files

| File | What |
|---|---|
| `tbl_editor.py` | the GUI editor |
| `tbl.py` | `.tbl` crypto + parser + repack (also a CLI) |
| `tbl_schemas.py` | human-readable column names for known tables |
| `TBL-Editoru.bat` | double-click launcher |

## License

MIT — see [LICENSE](LICENSE).
