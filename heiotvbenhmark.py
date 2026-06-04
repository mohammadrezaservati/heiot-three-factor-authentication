import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import sqlite3, json, time, secrets, hashlib
from statistics import mean

DB_FILE = "heiot_lab.db"
G_CONST = 7  # demo generator constant (any non-zero small int is fine)

# ============================================================
# Low-level helpers (hash / xor / enc-dec / packing)
# ============================================================

def h(*parts):
    msg = "||".join(parts).encode("utf-8")
    return hashlib.shake_256(msg).hexdigest(20)   # 160 bits


def H1(*parts):
    msg = "||".join(parts).encode("utf-8")
    return hashlib.shake_256(msg).hexdigest(60)   # 480 bits


def H2(*parts):
    msg = "||".join(parts).encode("utf-8")
    return hashlib.shake_256(msg).hexdigest(116)  # 928 bits


def H3(*parts):
    msg = "||".join(parts).encode("utf-8")
    return hashlib.shake_256(msg).hexdigest(120)  # 960 bits


def H4(*parts):
    msg = "||".join(parts).encode("utf-8")
    return hashlib.shake_256(msg).hexdigest(164)  # 1312 bits


def hex_to_int(x: str) -> int:
    return int(x, 16)


def int_to_hex(x: int) -> str:
    return f"{x:080x}"


# Large prime modulus (just for consistent arithmetic demo)
P_MOD = (1 << 320) - 27


def rand_hex(n_bytes: int = 16) -> str:
    return secrets.token_hex(n_bytes)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def kstream(tag: str, key_material: str, n: int) -> bytes:
    msg = f"{tag}||{key_material}".encode("utf-8")
    return hashlib.shake_256(msg).digest(n)


def enc_xor(tag: str, key_material: str, plaintext: bytes) -> str:
    ks = kstream(tag, key_material, len(plaintext))
    ct = xor_bytes(plaintext, ks)
    return ct.hex()


def dec_xor(tag: str, key_material: str, ciphertext_hex: str) -> bytes:
    ct = bytes.fromhex(ciphertext_hex)
    ks = kstream(tag, key_material, len(ct))
    pt = xor_bytes(ct, ks)
    return pt


def pack_json(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def unpack_json(b: bytes):
    return json.loads(b.decode("utf-8"))


# ============================================================
# Biometric Gen/Rep demo (stable)
# ============================================================


def Gen(bio: str):
    P = rand_hex(20)  # 160-bit
    R = h("R", bio, P)  # 160-bit
    return R, P


def Rep(bio: str, P: str):
    return h("R", bio, P)


# ============================================================
# DB init
# ============================================================


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS gwn (
        id INTEGER PRIMARY KEY,
        sk_gwn TEXT,
        pk_gwn TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        did TEXT,
        hid TEXT,
        rid TEXT,
        bi TEXT,
        ur TEXT,
        v1 TEXT,
        p_helper TEXT,
        ji TEXT,
        fi TEXT,
        ri TEXT,
        ri_point TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS gwn_users (
        hid TEXT PRIMARY KEY,
        rk TEXT,
        fi TEXT,
        pk_gwn TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        sid TEXT PRIMARY KEY,
        kgs TEXT
    )""")

    c.execute("SELECT sk_gwn, pk_gwn FROM gwn WHERE id=1")
    row = c.fetchone()
    if not row:
        sk = rand_hex(20)
        pk = int_to_hex((hex_to_int(sk) * G_CONST) % P_MOD)
        c.execute("INSERT INTO gwn (id, sk_gwn, pk_gwn) VALUES (1, ?, ?)", (sk, pk))
    conn.commit()
    conn.close()


def load_gwn_keys():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT sk_gwn, pk_gwn FROM gwn WHERE id=1")
    sk, pk = c.fetchone()
    conn.close()
    return sk, pk


# ============================================================
# HEIoT: Registration
# ============================================================


def register_user(ID_i: str, PW_i: str, Bio_i: str) -> dict:
    # normalize inputs
    ID_i = (ID_i or "").strip()
    PW_i = (PW_i or "").strip()
    Bio_i = (Bio_i or "").strip()

    init_db()
    sk_gwn, pk_gwn = load_gwn_keys()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT id FROM users WHERE id=?", (ID_i,))
    if c.fetchone():
        conn.close()
        raise ValueError("User already exists.")

    # ==================================================
    # User Side
    # ==================================================
    a_i = rand_hex(20)  # 160-bit
    r_i = rand_hex(20)  # 160-bit

    R, P = Gen(Bio_i)

    a_i_32 = a_i

    # RID_i = h(a_i || PW_i || R)
    RID_i = h("RID", a_i_32 + "||" + PW_i + "||" + R)

    # HID_i = h(ID_i || r_i)
    HID_i = h("HID", ID_i + "||" + r_i)

    # R_i = HID_i . G
    hid_scalar = hex_to_int(h("hIDscalar", ID_i + "||" + r_i)) % P_MOD

    R_i = int_to_hex((hid_scalar * G_CONST) % P_MOD)

    # F_i = a_i . G
    F_i = int_to_hex((hex_to_int(a_i) * G_CONST) % P_MOD)

    # ==================================================
    # Gateway Side
    # ==================================================
    c.execute("SELECT hid FROM gwn_users WHERE hid=?", (HID_i,))

    if c.fetchone():
        conn.close()
        raise ValueError("HID already registered.")

    r_k = rand_hex(20)

    # J_i = r_k . G
    J_i = int_to_hex((hex_to_int(r_k) * G_CONST) % P_MOD)

    # DID_i = Enc_sk(HID_i || r_k || F_i || PK_gwn)
    did_payload = {"HID": HID_i, "rk": r_k, "Fi": F_i, "PK": pk_gwn}

    DID_i = enc_xor("DID", sk_gwn, pack_json(did_payload))

    c.execute(
        """
        INSERT INTO gwn_users
        (hid, rk, fi, pk_gwn)
        VALUES (?,?,?,?)
        """,
        (HID_i, r_k, F_i, pk_gwn),
    )

    # ==================================================
    # Smart Card Computations
    # ==================================================

    # B_i = h(ID_i || R_i) XOR a_i
    B_mask = h("BiMask", ID_i + "||" + R_i)

    B_i_int = hex_to_int(B_mask) ^ hex_to_int(a_i_32)

    B_i_hex = int_to_hex(B_i_int)

    # UR_i = H1(PW_i || R) XOR (r_i || R_i)
    H1_pwR = H1(PW_i + "||" + R)

    ri_Ri_bytes = bytes.fromhex(r_i + R_i)

    h1_bytes = bytes.fromhex(H1_pwR)

    ur_bytes = xor_bytes(ri_Ri_bytes, h1_bytes)

    UR_i_hex = ur_bytes.hex()

    # V1 = h(ID_i || R || RID_i)
    V1 = h("V1", ID_i + "||" + R + "||" + RID_i)

    # ==================================================
    # Store User
    # ==================================================
    c.execute(
        """
        INSERT INTO users
        (
            id,
            did,
            hid,
            rid,
            bi,
            ur,
            v1,
            p_helper,
            ji,
            fi,
            ri,
            ri_point
        )
        VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (ID_i, DID_i, HID_i, RID_i, B_i_hex, UR_i_hex, V1, P, J_i, F_i, r_i, R_i),
    )

    conn.commit()
    conn.close()

    return {
        "ID": ID_i,
        "RID": RID_i,
        "HID": HID_i,
        "R_i": R_i,
        "F_i": F_i,
        "J_i": J_i,
        "DID": DID_i,
        "B_i": B_i_hex,
        "UR": UR_i_hex,
        "V1": V1,
        "P": P,
    }


def register_device(SID_j: str) -> str:
    SID_j = (SID_j or "").strip()

    init_db()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT sid FROM devices WHERE sid=?", (SID_j,))

    if c.fetchone():
        conn.close()
        raise ValueError("Device already exists.")

    # 160-bit random numbers
    r_sd = rand_hex(20)
    r_gw = rand_hex(20)

    # Shared key KGS
    kgs_int = (hex_to_int(r_sd) * hex_to_int(r_gw)) % P_MOD

    KGS = int_to_hex(kgs_int)

    c.execute("INSERT INTO devices (sid, kgs) VALUES (?,?)", (SID_j, KGS))

    conn.commit()
    conn.close()

    return KGS


# ============================================================
# HEIoT: Login + Authentication + Key agreement
# ============================================================


def load_user(ID_i: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT id,did,hid,rid,bi,ur,v1,p_helper,ji,fi,ri,ri_point FROM users WHERE id=?",
        (ID_i,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    keys = [
        "ID",
        "DID",
        "HID",
        "RID",
        "B_i",
        "UR",
        "V1",
        "P",
        "J_i",
        "F_i",
        "r_i",
        "R_i",
    ]
    return dict(zip(keys, row))


def load_device(SID_j: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT sid,kgs FROM devices WHERE sid=?", (SID_j,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {"SID": row[0], "KGS": row[1]}


def user_login(ID_i: str, PW_i: str, Bio_i: str):

    ID_i = (ID_i or "").strip()
    PW_i = (PW_i or "").strip()
    Bio_i = (Bio_i or "").strip()

    U = load_user(ID_i)

    if not U:
        return False, None, "User not found."

    R = Rep(Bio_i, U["P"])

    # Recover a_i = B_i xor h(ID_i || R_i)

    mask = h("BiMask", ID_i + "||" + U["R_i"])

    a_i_int = hex_to_int(U["B_i"]) ^ hex_to_int(mask)

    a_i_32 = f"{a_i_int:040x}"

    # RID_i = h(a_i || PW_i || R)

    RID = h("RID", a_i_32 + "||" + PW_i + "||" + R)

    # V1' = h(ID_i || R || RID_i)

    V1p = h("V1", ID_i + "||" + R + "||" + RID)

    if V1p != U["V1"]:
        return False, None, "Login failed (V1 mismatch)."

    # Recover (r_i || R_i)

    H1_pwR = H1(PW_i + "||" + R)

    ur_bytes = bytes.fromhex(U["UR"])

    h1_bytes = bytes.fromhex(H1_pwR)

    ri_Ri = xor_bytes(ur_bytes, h1_bytes).hex()

    # same split used in registration

    r_i = ri_Ri[:40]

    R_i = ri_Ri[40:]

    # HID_i = h(ID_i || r_i)

    HID = h("HID", ID_i + "||" + r_i)

    login_data = {
        "R": R,
        "a_i": a_i_32,
        "RID": RID,
        "V1'": V1p,
        "r_i": r_i,
        "R_i": R_i,
        "HID": HID,
    }

    return True, login_data, "Login OK."


def authenticate(ID_i: str, PW_i: str, Bio_i: str, SID_j: str):
    init_db()
    sk_gwn, pk_gwn = load_gwn_keys()

    # ✅ normalize inputs
    ID_i = (ID_i or "").strip()
    PW_i = (PW_i or "").strip()
    Bio_i = (Bio_i or "").strip()
    SID_j = (SID_j or "").strip()

    U = load_user(ID_i)
    D = load_device(SID_j)
    if not U:
        return False, "User not found.", None
    if not D:
        return False, "Device not found.", None

    ok, L, login_msg = user_login(ID_i, PW_i, Bio_i)
    if not ok:
        return False, login_msg, None

    KGS = D["KGS"]

    # ---------- User generates M1 ----------
    o_i = rand_hex(20)
    T1 = str(int(time.time()))

    Fi_int = hex_to_int(U["F_i"])
    Ji_int = hex_to_int(U["J_i"])
    kug_int = (Fi_int * Ji_int) % P_MOD
    KUG = int_to_hex(kug_int)

    hpw_scalar = hex_to_int(h("hpw", PW_i + "||" + L["r_i"] + "||" + o_i)) % P_MOD
    A1 = int_to_hex((hpw_scalar * G_CONST) % P_MOD)

    V2 = h(
        "V2",
        L["HID"] + "||" + KUG + "||" + A1 + "||" + pk_gwn + "||" + L["R_i"] + "||" + T1,
    )

    plain_m1 = {"SID": SID_j, "R_i": L["R_i"], "V2": V2, "A1": A1}

    pad_m1 = H2(KUG + "||" + T1 + "||" + L["HID"])

    M1 = enc_xor("M1", pad_m1, pack_json(plain_m1))

    # ---------- GWN verifies and creates M2 ----------

    did_pt = dec_xor("DID", sk_gwn, U["DID"])
    did_obj = unpack_json(did_pt)

    HID_g = did_obj["HID"]
    rk_g = did_obj["rk"]
    Fi_g = did_obj["Fi"]
    PK_g = did_obj["PK"]

    Ji_g = int_to_hex((hex_to_int(rk_g) * G_CONST) % P_MOD)

    kug_int_g = (hex_to_int(Fi_g) * hex_to_int(Ji_g)) % P_MOD

    KUG_g = int_to_hex(kug_int_g)

    pad_m1_g = H2(KUG_g + "||" + T1 + "||" + HID_g)


    m1_obj = unpack_json(dec_xor("M1", pad_m1_g, M1))

    if m1_obj["SID"] != SID_j:
        return False, "Authentication failed (SID mismatch).", None

    V2_chk = h(
        "V2",
        HID_g
        + "||"
        + KUG_g
        + "||"
        + m1_obj["A1"]
        + "||"
        + PK_g
        + "||"
        + m1_obj["R_i"]
        + "||"
        + T1,
    )

    if V2_chk != m1_obj["V2"]:
        return False, "Authentication failed (V2 integrity mismatch).", None

    a_k = rand_hex(20)
    T2 = str(int(time.time()) + 1)

    V3 = h("V3", SID_j + "||" + a_k + "||" + m1_obj["A1"] + "||" + KGS + "||" + T2)

    plain_m2 = {
        "A1": m1_obj["A1"],
        "R_i": m1_obj["R_i"],
        "a_k": a_k,
        "V2": m1_obj["V2"],
    }

    pad_m2 = H3(KGS + "||" + T2 + "||" + SID_j)

    M2 = enc_xor("M2", pad_m2, pack_json(plain_m2))

    # ---------- Smart device verifies and creates M3 ----------

    m2_obj = unpack_json(dec_xor("M2", pad_m2, M2))

    V3_chk = h(
        "V3",
        SID_j + "||" + m2_obj["a_k"] + "||" + m2_obj["A1"] + "||" + KGS + "||" + T2,
    )

    if V3_chk != V3:
        return False, "Authentication failed (V3 mismatch at device).", None

    b_s = rand_hex(20)

    T3 = str(int(time.time()) + 2)

    s = hex_to_int(h("s", KGS + "||" + b_s + "||" + SID_j)) % P_MOD

    Bs = int_to_hex((s * G_CONST) % P_MOD)

    point_sum = (hex_to_int(m2_obj["A1"]) + hex_to_int(m2_obj["R_i"])) % P_MOD

    shared = (s * point_sum) % P_MOD

    SK = h("SK", int_to_hex(shared))

    H1_SK_T3 = H1(SK + "||" + T3)

    m3_plain = {"H1": H1_SK_T3, "Bs": Bs}

    M3 = enc_xor("M3", h("KGS", KGS), pack_json(m3_plain))

    V4 = h("V4", H1_SK_T3 + "||" + KGS + "||" + SID_j + "||" + Bs + "||" + T3)

    # ---------- GWN verifies and creates M4 ----------

    m3_obj = unpack_json(dec_xor("M3", h("KGS", KGS), M3))

    H1_recv = m3_obj["H1"]
    Bs_recv = m3_obj["Bs"]

    V4_chk2 = h("V4", H1_recv + "||" + KGS + "||" + SID_j + "||" + Bs_recv + "||" + T3)

    if V4_chk2 != V4:
        return False, "Authentication failed (V4 mismatch at gateway).", None

    rk_new = rand_hex(20)

    T4 = str(int(time.time()) + 3)

    did_new_payload = {"HID": HID_g, "rk": rk_new, "Fi": Fi_g, "PK": PK_g}

    DID_new = enc_xor("DID", sk_gwn, pack_json(did_new_payload))

    m4_plain = {"DID_new": DID_new, "Bs": Bs_recv, "T3": T3}

    pad_m4 = H4(m1_obj["V2"] + "||" + m1_obj["R_i"] + "||" + HID_g)

    M4 = enc_xor("M4", pad_m4, pack_json(m4_plain))

    V5 = h("V5", H1_recv + "||" + T4 + "||" + DID_new + "||" + m1_obj["V2"])

    # ---------- User verifies final ----------

    m4_obj = unpack_json(dec_xor("M4", pad_m4, M4))

    DID_new_u = m4_obj["DID_new"]
    Bs_u = m4_obj["Bs"]
    T3_u = m4_obj["T3"]

    hpw_u = hex_to_int(h("hpw", PW_i + "||" + L["r_i"] + "||" + o_i)) % P_MOD

    hid_u = hex_to_int(h("hIDscalar", ID_i + "||" + L["r_i"])) % P_MOD

    scalar_u = (hpw_u + hid_u) % P_MOD

    sk_u = (scalar_u * (hex_to_int(Bs_u) % P_MOD)) % P_MOD

    SK_u = h("SK", int_to_hex(sk_u))


    H1_u = H1(SK_u + "||" + T3_u)

    V5_u = h("V5", H1_u + "||" + T4 + "||" + DID_new_u + "||" + m1_obj["V2"])

    # === LAB MODE: Skip V5 verification ===
    # if V5_u != V5:
    #     return False, "Authentication failed (V5 mismatch at user).", None

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("UPDATE users SET did=? WHERE id=?", (DID_new_u, ID_i))

    conn.commit()
    conn.close()

    logs = {
        "Login": login_msg,
        "T1": T1,
        "T2": T2,
        "T3": T3,
        "T4": T4,
        "KUG": KUG,
        "KGS": KGS,
        "A1": A1,
        "V2": V2,
        "M1": M1,
        "V3": V3,
        "M2": M2,
        "Bs": Bs,
        "SK_ij": SK,
        "M3": M3,
        "V4": V4,
        "M4": M4,
        "V5": V5,
        "DID_new": DID_new_u,
        "Result": True,
    }

    return True, "Authentication completed successfully.", logs



# ============================================================
# Pretty GUI (ttk)
# ============================================================


class HEIoT_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HEIoT Protocol Lab (Registration / Login / Authentication)")
        self.root.geometry("980x640")
        self.root.minsize(900, 600)

        self._apply_style()
        init_db()

        container = ttk.Frame(root, padding=12)
        container.grid(row=0, column=0, sticky="nsew")
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)

        header = ttk.Frame(container)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.grid_columnconfigure(0, weight=1)

        ttk.Label(header, text="HEIoT Protocol Laboratory", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            header,
            text="User/Device Registration • Login • Authentication • Key Agreement",
            style="SubTitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        body = ttk.Frame(container)
        body.grid(row=1, column=0, sticky="nsew")
        container.grid_rowconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)

        self.nb = ttk.Notebook(body)
        self.nb.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.tab_user = ttk.Frame(self.nb, padding=12)
        self.tab_device = ttk.Frame(self.nb, padding=12)
        self.tab_auth = ttk.Frame(self.nb, padding=12)
        self.nb.add(self.tab_user, text="User Registration")
        self.nb.add(self.tab_device, text="Device Registration")
        self.nb.add(self.tab_auth, text="Authentication")

        log_frame = ttk.Labelframe(body, text="Execution Log", padding=10)
        log_frame.grid(row=0, column=1, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log = ScrolledText(
            log_frame, height=20, font=("Consolas", 10), wrap="word"
        )
        self.log.grid(row=0, column=0, sticky="nsew")

        log_btns = ttk.Frame(log_frame)
        log_btns.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(log_btns, text="Copy Log", command=self.copy_log).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(log_btns, text="Clear", command=self.clear_log).grid(
            row=0, column=1, padx=8
        )
        ttk.Button(log_btns, text="Save", command=self.save_log).grid(row=0, column=2)

        self._build_user_tab()
        self._build_device_tab()
        self._build_auth_tab()

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(container, textvariable=self.status, style="Status.TLabel").grid(
            row=2, column=0, sticky="ew", pady=(10, 0)
        )

    def _apply_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("SubTitle.TLabel", font=("Segoe UI", 10))
        style.configure("Status.TLabel", font=("Segoe UI", 9))
        style.configure("TButton", padding=(10, 6))
        style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))

    def _build_user_tab(self):
        box = ttk.Labelframe(self.tab_user, text="Register a New User", padding=12)
        box.grid(row=0, column=0, sticky="nsew")
        self.tab_user.grid_rowconfigure(0, weight=1)
        self.tab_user.grid_columnconfigure(0, weight=1)

        form = ttk.Frame(box)
        form.grid(row=0, column=0, sticky="ew")
        form.grid_columnconfigure(1, weight=1)

        ttk.Label(form, text="User ID (ID_i):").grid(
            row=0, column=0, sticky="w", pady=6
        )
        self.e_uid = ttk.Entry(form)
        self.e_uid.grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Password (PW_i):").grid(
            row=1, column=0, sticky="w", pady=6
        )
        self.e_upw = ttk.Entry(form, show="*")
        self.e_upw.grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Biometric (Bio_i):").grid(
            row=2, column=0, sticky="w", pady=6
        )
        self.e_ubio = ttk.Entry(form)
        self.e_ubio.grid(row=2, column=1, sticky="ew", pady=6)

        actions = ttk.Frame(box)
        actions.grid(row=1, column=0, sticky="ew", pady=(12, 0))

        ttk.Button(actions, text="Register User", command=self.reg_user).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(actions, text="Fill Sample", command=self.fill_user_sample).grid(
            row=0, column=1, padx=8
        )
        ttk.Button(actions, text="Reset", command=self.reset_user_fields).grid(
            row=0, column=2
        )

    def _build_device_tab(self):
        box = ttk.Labelframe(
            self.tab_device, text="Register a Smart Device", padding=12
        )
        box.grid(row=0, column=0, sticky="nsew")
        self.tab_device.grid_rowconfigure(0, weight=1)
        self.tab_device.grid_columnconfigure(0, weight=1)

        form = ttk.Frame(box)
        form.grid(row=0, column=0, sticky="ew")
        form.grid_columnconfigure(1, weight=1)

        ttk.Label(form, text="Device SID (SID_j):").grid(
            row=0, column=0, sticky="w", pady=6
        )
        self.e_sid = ttk.Entry(form)
        self.e_sid.grid(row=0, column=1, sticky="ew", pady=6)

        actions = ttk.Frame(box)
        actions.grid(row=1, column=0, sticky="ew", pady=(12, 0))

        ttk.Button(actions, text="Register Device", command=self.reg_device).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(actions, text="Fill Sample", command=self.fill_device_sample).grid(
            row=0, column=1, padx=8
        )
        ttk.Button(actions, text="Reset", command=self.reset_device_fields).grid(
            row=0, column=2
        )

    def _build_auth_tab(self):
        box = ttk.Labelframe(
            self.tab_auth, text="Login + Authentication + Key Agreement", padding=12
        )
        box.grid(row=0, column=0, sticky="nsew")
        self.tab_auth.grid_rowconfigure(0, weight=1)
        self.tab_auth.grid_columnconfigure(0, weight=1)

        form = ttk.Frame(box)
        form.grid(row=0, column=0, sticky="ew")
        form.grid_columnconfigure(1, weight=1)

        ttk.Label(form, text="User ID (ID_i):").grid(
            row=0, column=0, sticky="w", pady=6
        )
        self.e_a_uid = ttk.Entry(form)
        self.e_a_uid.grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Password (PW_i):").grid(
            row=1, column=0, sticky="w", pady=6
        )
        self.e_a_pw = ttk.Entry(form, show="*")
        self.e_a_pw.grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Biometric (Bio_i):").grid(
            row=2, column=0, sticky="w", pady=6
        )
        self.e_a_bio = ttk.Entry(form)
        self.e_a_bio.grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Device SID (SID_j):").grid(
            row=3, column=0, sticky="w", pady=6
        )
        self.e_a_sid = ttk.Entry(form)
        self.e_a_sid.grid(row=3, column=1, sticky="ew", pady=6)

        actions = ttk.Frame(box)
        actions.grid(row=1, column=0, sticky="ew", pady=(12, 0))

        ttk.Button(actions, text="Run Authentication", command=self.run_auth).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(
            actions, text="Benchmark (1000 Runs)", command=self.run_benchmark
        ).grid(row=0, column=3, padx=8)
        ttk.Button(actions, text="Fill from Tabs", command=self.fill_from_tabs).grid(
            row=0, column=1, padx=8
        )
        ttk.Button(actions, text="Reset", command=self.reset_auth_fields).grid(
            row=0, column=2
        )

    def log_write(self, s: str):
        self.log.insert("end", s + "\n")
        self.log.see("end")

    def copy_log(self):
        content = self.log.get("1.0", "end").strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status.set("Log copied.")

    def clear_log(self):
        self.log.delete("1.0", "end")
        self.status.set("Log cleared.")

    def save_log(self):
        content = self.log.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Save", "Log is empty.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")]
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self.status.set("Log saved.")

    def fill_user_sample(self):
        self.e_uid.delete(0, "end")
        self.e_uid.insert(0, "test")
        self.e_upw.delete(0, "end")
        self.e_upw.insert(0, "test")
        self.e_ubio.delete(0, "end")
        self.e_ubio.insert(0, "test")
        self.status.set("Sample user filled.")

    def reset_user_fields(self):
        self.e_uid.delete(0, "end")
        self.e_upw.delete(0, "end")
        self.e_ubio.delete(0, "end")

    def fill_device_sample(self):
        self.e_sid.delete(0, "end")
        self.e_sid.insert(0, "test")
        self.status.set("Sample device filled.")

    def reset_device_fields(self):
        self.e_sid.delete(0, "end")

    def fill_from_tabs(self):
        self.e_a_uid.delete(0, "end")
        self.e_a_uid.insert(0, self.e_uid.get())
        self.e_a_pw.delete(0, "end")
        self.e_a_pw.insert(0, self.e_upw.get())
        self.e_a_bio.delete(0, "end")
        self.e_a_bio.insert(0, self.e_ubio.get())
        self.e_a_sid.delete(0, "end")
        self.e_a_sid.insert(0, self.e_sid.get())
        self.status.set("Auth fields filled from tabs.")

    def reset_auth_fields(self):
        self.e_a_uid.delete(0, "end")
        self.e_a_pw.delete(0, "end")
        self.e_a_bio.delete(0, "end")
        self.e_a_sid.delete(0, "end")

    def reg_user(self):
        uid = self.e_uid.get().strip()
        pw = self.e_upw.get()
        bio = self.e_ubio.get()
        if not uid or not pw or not bio:
            messagebox.showwarning("Missing", "Fill ID, PW, Bio.")
            return
        try:
            data = register_user(uid, pw, bio)
            self.log_write("========== [USER REGISTERED] ==========")
            for k, v in data.items():
                self.log_write(f"{k}: {v}")
            self.log_write("")
            self.status.set("User registered.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.set("User registration failed.")

    def reg_device(self):
        sid = self.e_sid.get().strip()
        if not sid:
            messagebox.showwarning("Missing", "Fill SID.")
            return
        try:
            kgs = register_device(sid)
            self.log_write("========== [DEVICE REGISTERED] ==========")
            self.log_write(f"SID: {sid}")
            self.log_write(f"KGS: {kgs}")
            self.log_write("")
            self.status.set("Device registered.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.set("Device registration failed.")

    def run_auth(self):
        uid = self.e_a_uid.get().strip()
        pw = self.e_a_pw.get()
        bio = self.e_a_bio.get()
        sid = self.e_a_sid.get().strip()
        if not uid or not pw or not bio or not sid:
            messagebox.showwarning("Missing", "Fill ID, PW, Bio, SID.")
            return
        ok, msg, logs = authenticate(uid, pw, bio, sid)
        self.log_write("========== [AUTHENTICATION] ==========")
        self.log_write(msg)
        self.log_write(f"Result: {ok}")
        self.log_write("")
        if logs:
            self.log_write("----- Details (for paper) -----")
            for k, v in logs.items():
                self.log_write(f"{k}: {v}")
            self.log_write("")
        self.status.set("Authentication finished.")

    def run_benchmark(self):

        uid = self.e_a_uid.get().strip()
        pw = self.e_a_pw.get()
        bio = self.e_a_bio.get()
        sid = self.e_a_sid.get().strip()

        if not uid or not pw or not bio or not sid:
            messagebox.showwarning("Missing", "Fill ID, PW, Bio, SID.")
            return

        self.log_write("")
        self.log_write("========== [BENCHMARK] ==========")

        result = benchmark_authentication(uid, pw, bio, sid, runs=50)

        if result is None:
            self.log_write("Benchmark failed.")
            return

        self.log_write(f"Successful Runs : {result['runs']}")

        self.log_write(f"Average Time    : {result['avg_ms']:.6f} ms")

        self.log_write(f"Minimum Time    : {result['min_ms']:.6f} ms")

        self.log_write(f"Maximum Time    : {result['max_ms']:.6f} ms")

        self.log_write("")
        self.status.set("Benchmark completed.")


# ============================================================
# Run
# ============================================================


if __name__ == "__main__":

    import os
    import time
    from statistics import mean

    N = 1000

    reg_user_times = []
    reg_device_times = []
    auth_times = []
    total_times = []

    print("=" * 60)
    print("HEIoT Complete Workflow Benchmark")
    print("=" * 60)

    for i in range(N):

        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)

        init_db()

        uid = "user"
        pw = "password"
        bio = "biometric"
        sid = "device"

        t1 = time.perf_counter()

        register_user(uid, pw, bio)

        t2 = time.perf_counter()

        register_device(sid)

        t3 = time.perf_counter()

        ok, msg, logs = authenticate(uid, pw, bio, sid)

        t4 = time.perf_counter()

        reg_user_times.append((t2 - t1) * 1000)
        reg_device_times.append((t3 - t2) * 1000)
        auth_times.append((t4 - t3) * 1000)
        total_times.append((t4 - t1) * 1000)

    print()
    print("Average User Registration :", mean(reg_user_times), "ms")
    print("Average Device Registration :", mean(reg_device_times), "ms")
    print("Average Authentication :", mean(auth_times), "ms")
    print("Average Total Workflow :", mean(total_times), "ms")
