#!/usr/bin/env python3
"""
lock - compacta e criptografa pastas/arquivos no formato .ziplock

Formato do arquivo (nenhum cabeçalho fixo, tudo parece dado aleatório):
    [salt 16 bytes][prefixo de nonce 4 bytes][bloco][bloco]...[bloco final]
Cada bloco é AES-256-GCM (até 1 MiB de dados + 16 bytes de tag).
O conteúdo é um tar.gz (nomes dos arquivos incluídos) criptografado por inteiro.
A chave vem da senha via scrypt.

Uso:
    python lock.py                       -> abre a interface gráfica
    python lock.py arquivo.ziplock       -> abre a interface gráfica já para extrair
    python lock.py pack  PASTA [-o saida.ziplock]
    python lock.py unpack ARQ.ziplock [-o pasta_destino]
    python lock.py list  ARQ.ziplock
    python lock.py register              -> associa .ziplock ao lock (Windows)

Dependência: pip install cryptography
"""
import argparse
import getpass
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

EXT = ".ziplock"
CHUNK = 1024 * 1024
TAG = 16
SALT_LEN = 16
PREFIX_LEN = 4
SCRYPT_N = 2 ** 17  # ~128 MB de RAM por derivação; deixa ataques de força bruta caros


class WrongPassword(Exception):
    pass


class BadFile(Exception):
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(password.encode("utf-8"))


def _nonce(prefix: bytes, i: int) -> bytes:
    return prefix + struct.pack(">Q", i)


class EncWriter:
    """Objeto de escrita que criptografa em blocos AES-GCM."""

    def __init__(self, f, key):
        self.f = f
        self.aes = AESGCM(key)
        self.prefix = os.urandom(PREFIX_LEN)
        self.i = 0
        self.buf = bytearray()
        f.write(self.prefix)

    def _emit(self, data, last):
        aad = b"\x01" if last else b"\x00"
        self.f.write(self.aes.encrypt(_nonce(self.prefix, self.i), bytes(data), aad))
        self.i += 1

    def write(self, data):
        self.buf += data
        while len(self.buf) > CHUNK:
            self._emit(self.buf[:CHUNK], False)
            del self.buf[:CHUNK]
        return len(data)

    def flush(self):
        pass

    def close(self):
        self._emit(self.buf, True)
        self.buf.clear()


class DecReader:
    """Objeto de leitura que descriptografa e valida cada bloco."""

    def __init__(self, f, key):
        self.f = f
        self.aes = AESGCM(key)
        self.prefix = f.read(PREFIX_LEN)
        if len(self.prefix) < PREFIX_LEN:
            raise BadFile("Arquivo inválido.")
        self.i = 0
        self.buf = bytearray()
        self.done = False
        self.next = f.read(CHUNK + TAG)
        if len(self.next) < TAG:
            raise BadFile("Arquivo inválido ou corrompido.")
        self._fill()  # valida a senha já no primeiro bloco

    def _fill(self):
        cur = self.next
        self.next = self.f.read(CHUNK + TAG)
        last = not self.next
        aad = b"\x01" if last else b"\x00"
        try:
            pt = self.aes.decrypt(_nonce(self.prefix, self.i), cur, aad)
        except InvalidTag:
            raise WrongPassword("Senha errada ou arquivo corrompido.")
        self.i += 1
        self.buf += pt
        if last:
            self.done = True

    def read(self, n=-1):
        while (n < 0 or len(self.buf) < n) and not self.done:
            self._fill()
        if n < 0:
            n = len(self.buf)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


def pack(src, out, password):
    src = Path(src)
    if not src.exists():
        raise FileNotFoundError(f"Não encontrei: {src}")
    out = str(out)
    if not out.lower().endswith(EXT):
        out += EXT
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    tmp = out + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(salt)
            w = EncWriter(f, key)
            with tarfile.open(fileobj=w, mode="w|gz") as tar:
                tar.add(str(src), arcname=src.name)
            w.close()
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return out


def _open(path, password):
    f = open(path, "rb")
    try:
        salt = f.read(SALT_LEN)
        if len(salt) < SALT_LEN:
            raise BadFile("Arquivo inválido.")
        reader = DecReader(f, derive_key(password, salt))
    except Exception:
        f.close()
        raise
    return f, reader


def unpack(path, dest, password):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    kw = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
    f, reader = _open(path, password)
    with f:
        try:
            with tarfile.open(fileobj=reader, mode="r|gz") as tar:
                for m in tar:
                    if not (m.isfile() or m.isdir()):
                        continue
                    target = (root / m.name).resolve()
                    if target != root and root not in target.parents:
                        raise BadFile("Caminho suspeito dentro do arquivo.")
                    tar.extract(m, str(root), **kw)
        except tarfile.TarError as e:
            raise BadFile(f"Conteúdo inválido: {e}")
    return str(root)


def list_contents(path, password):
    items = []
    f, reader = _open(path, password)
    with f:
        try:
            with tarfile.open(fileobj=reader, mode="r|gz") as tar:
                for m in tar:
                    items.append((m.name, m.size, m.isdir()))
        except tarfile.TarError as e:
            raise BadFile(f"Conteúdo inválido: {e}")
    return items


def wipe(folder):
    """Apaga a pasta temporária (melhor esforço; não é apagamento seguro de SSD)."""
    def onerr(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    shutil.rmtree(folder, onerror=onerr)


def open_session(path, password):
    """Extrai para uma pasta temporária. Retorna (pasta_temp, pasta_de_trabalho)."""
    tmp = tempfile.mkdtemp(prefix="lock_")
    try:
        unpack(path, tmp, password)
        entries = os.listdir(tmp)
        if len(entries) != 1:
            raise BadFile("Conteúdo inesperado dentro do arquivo.")
    except Exception:
        wipe(tmp)
        raise
    return tmp, os.path.join(tmp, entries[0])


def close_session(path, password, tmp, top):
    """Compacta de volta no .ziplock e só então apaga a pasta temporária."""
    pack(top, path, password)  # se falhar, levanta erro e a pasta temporária é mantida
    wipe(tmp)


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- Windows

def register_extension():
    import winreg
    if getattr(sys, "frozen", False):
        cmd = f'"{sys.executable}" "%1"'
    else:
        py = Path(sys.executable)
        pyw = py.with_name("pythonw.exe")
        runner = pyw if pyw.exists() else py
        cmd = f'"{runner}" "{Path(__file__).resolve()}" "%1"'
    base = r"Software\Classes"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\.ziplock") as k:
        winreg.SetValue(k, "", winreg.REG_SZ, "lock.ziplock")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\lock.ziplock") as k:
        winreg.SetValue(k, "", winreg.REG_SZ, "Pasta protegida (lock)")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\lock.ziplock\shell\open\command") as k:
        winreg.SetValue(k, "", winreg.REG_SZ, cmd)
    try:
        import ctypes
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except Exception:
        pass


# ---------------------------------------------------------------- GUI

def gui(initial=None):
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog

    root = tk.Tk()
    root.title("lock")
    root.geometry("360x325")
    root.resizable(False, False)

    status = tk.StringVar(value="Pronto.")
    busy = {"v": False}
    sessions = {"n": 0}

    def ask_password(confirm=False):
        pw = simpledialog.askstring("Senha", "Digite a senha:", show="*", parent=root)
        if not pw:
            return None
        if confirm:
            pw2 = simpledialog.askstring("Senha", "Confirme a senha:", show="*", parent=root)
            if pw != pw2:
                messagebox.showerror("lock", "As senhas não conferem.", parent=root)
                return None
        return pw

    def run(task, ok_msg):
        if busy["v"]:
            return
        busy["v"] = True
        status.set("Trabalhando... (pode demorar em pastas grandes)")

        def worker():
            try:
                res = task()
                root.after(0, lambda: done(ok_msg(res) if callable(ok_msg) else ok_msg, None, res))
            except (WrongPassword, BadFile, OSError, ValueError) as e:
                root.after(0, lambda e=e: done(None, str(e), None))
            except Exception as e:
                root.after(0, lambda e=e: done(None, f"Erro: {e}", None))

        def done(msg, err, res):
            busy["v"] = False
            status.set("Pronto.")
            if err:
                messagebox.showerror("lock", err, parent=root)
            elif msg:
                messagebox.showinfo("lock", msg, parent=root)

        threading.Thread(target=worker, daemon=True).start()

    def do_pack(folder):
        src = filedialog.askdirectory(title="Escolha a pasta") if folder else \
            filedialog.askopenfilename(title="Escolha o arquivo")
        if not src:
            return
        default = Path(src).name + EXT
        out = filedialog.asksaveasfilename(
            title="Salvar como", initialfile=default, defaultextension=EXT,
            filetypes=[("lock", "*" + EXT)])
        if not out:
            return
        pw = ask_password(confirm=True)
        if not pw:
            return
        run(lambda: pack(src, out, pw), lambda r: f"Criado:\n{r}")

    def pick_ziplock():
        return filedialog.askopenfilename(
            title="Escolha o .ziplock", filetypes=[("lock", "*" + EXT), ("Todos", "*.*")])

    def do_unpack(path=None):
        path = path or pick_ziplock()
        if not path:
            return
        dest = filedialog.askdirectory(
            title="Extrair para...", initialdir=str(Path(path).parent))
        if not dest:
            return
        pw = ask_password()
        if not pw:
            return
        run(lambda: unpack(path, dest, pw), lambda r: f"Extraído em:\n{r}")

    def do_list(path=None):
        path = path or pick_ziplock()
        if not path:
            return
        pw = ask_password()
        if not pw:
            return
        if busy["v"]:
            return
        busy["v"] = True
        status.set("Lendo...")

        def worker():
            try:
                items = list_contents(path, pw)
                root.after(0, lambda: show(items, None))
            except Exception as e:
                root.after(0, lambda e=e: show(None, str(e)))

        def show(items, err):
            busy["v"] = False
            status.set("Pronto.")
            if err:
                messagebox.showerror("lock", err, parent=root)
                return
            win = tk.Toplevel(root)
            win.title(Path(path).name)
            txt = tk.Text(win, width=70, height=22)
            txt.pack(fill="both", expand=True)
            for name, size, isdir in items:
                txt.insert("end", f"{name}/\n" if isdir else f"{name}   ({human(size)})\n")
            txt.config(state="disabled")

        threading.Thread(target=worker, daemon=True).start()

    def do_open(path=None):
        path = path or pick_ziplock()
        if not path:
            return
        pw = ask_password()
        if not pw:
            return
        if busy["v"]:
            return
        busy["v"] = True
        status.set("Abrindo...")

        def worker():
            try:
                tmp, top = open_session(path, pw)
                root.after(0, lambda: opened(tmp, top))
            except Exception as e:
                root.after(0, lambda e=e: failed(str(e)))

        def failed(msg):
            busy["v"] = False
            status.set("Pronto.")
            messagebox.showerror("lock", msg, parent=root)

        def opened(tmp, top):
            busy["v"] = False
            status.set("Pronto.")
            sessions["n"] += 1
            try:
                os.startfile(top)
            except AttributeError:
                try:
                    subprocess.Popen(["xdg-open", top])
                except Exception:
                    pass
            except Exception:
                pass

            win = tk.Toplevel(root)
            win.title("Pasta aberta")
            win.geometry("340x150")
            win.resizable(False, False)
            tk.Label(win, text=Path(top).name, font=("Segoe UI", 12, "bold")).pack(pady=(14, 2))
            tk.Label(win, text="Mexa nos arquivos à vontade. Feche os programas que\n"
                               "estiverem usando eles antes de trancar.",
                     fg="gray").pack()
            state = {"working": False}
            btn = tk.Button(win, text="Fechar e trancar", width=24)
            btn.pack(pady=12)

            def lock_it():
                if state["working"]:
                    return
                state["working"] = True
                btn.config(state="disabled", text="Trancando...")

                def w():
                    try:
                        close_session(path, pw, tmp, top)
                        root.after(0, ok)
                    except Exception as e:
                        root.after(0, lambda e=e: err(str(e)))

                threading.Thread(target=w, daemon=True).start()

            def ok():
                sessions["n"] -= 1
                win.destroy()
                messagebox.showinfo("lock", "Pasta trancada de novo.", parent=root)

            def err(msg):
                state["working"] = False
                btn.config(state="normal", text="Fechar e trancar")
                messagebox.showerror(
                    "lock", f"{msg}\n\nA pasta aberta foi mantida em:\n{top}", parent=win)

            btn.config(command=lock_it)
            win.protocol("WM_DELETE_WINDOW", lock_it)

        threading.Thread(target=worker, daemon=True).start()

    def do_register():
        try:
            register_extension()
            messagebox.showinfo(
                "lock", "Pronto! Agora dois cliques em um .ziplock abrem o lock.", parent=root)
        except Exception as e:
            messagebox.showerror("lock", f"Não consegui associar: {e}", parent=root)

    tk.Label(root, text="lock", font=("Segoe UI", 18, "bold")).pack(pady=(14, 6))
    for text, cmd in [
        ("Compactar pasta", lambda: do_pack(True)),
        ("Compactar arquivo", lambda: do_pack(False)),
        ("Extrair .ziplock", do_unpack),
        ("Abrir e trancar", do_open),
        ("Ver conteúdo", do_list),
        ("Associar .ziplock a este app", do_register),
    ]:
        tk.Button(root, text=text, width=30, command=cmd).pack(pady=3)
    tk.Label(root, textvariable=status, fg="gray").pack(side="bottom", pady=8)

    def on_close():
        if sessions["n"] > 0:
            messagebox.showwarning(
                "lock", "Há uma pasta aberta. Feche e tranque antes de sair.", parent=root)
            return
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    if initial:
        root.after(200, lambda: do_unpack(initial))
    root.mainloop()


# ---------------------------------------------------------------- CLI

def main():
    argv = sys.argv[1:]
    if not argv:
        return gui()
    if len(argv) == 1 and argv[0].lower().endswith(EXT) and os.path.isfile(argv[0]):
        return gui(argv[0])

    p = argparse.ArgumentParser(prog="lock", description="Pastas protegidas (.ziplock)")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("pack", help="compacta e criptografa")
    a.add_argument("src")
    a.add_argument("-o", "--out")
    b = sub.add_parser("unpack", help="extrai")
    b.add_argument("file")
    b.add_argument("-o", "--out")
    c = sub.add_parser("list", help="lista o conteúdo")
    c.add_argument("file")
    sub.add_parser("register", help="associa .ziplock ao lock (Windows)")
    args = p.parse_args(argv)

    try:
        if args.cmd == "pack":
            pw = getpass.getpass("Senha: ")
            if pw != getpass.getpass("Confirme a senha: "):
                sys.exit("As senhas não conferem.")
            out = args.out or (Path(args.src).name + EXT)
            print("Criado:", pack(args.src, out, pw))
        elif args.cmd == "unpack":
            pw = getpass.getpass("Senha: ")
            dest = args.out or Path(args.file).with_suffix("")
            print("Extraído em:", unpack(args.file, dest, pw))
        elif args.cmd == "list":
            pw = getpass.getpass("Senha: ")
            for name, size, isdir in list_contents(args.file, pw):
                print(f"{name}/" if isdir else f"{name}  ({human(size)})")
        elif args.cmd == "register":
            register_extension()
            print("Extensão .ziplock associada ao lock.")
    except (WrongPassword, BadFile, OSError) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
