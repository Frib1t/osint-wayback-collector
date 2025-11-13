#!/usr/bin/env python3
"""
OSINT URL Checker v5.0 - 100% ESTABLE
"""

import requests
import sys
import argparse
import os
import threading
import queue
import signal
import re
from urllib.parse import urlparse, parse_qs
from pwn import *

# === COLORES ===
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"

# === VARIABLES GLOBALES ===
stop_event = threading.Event()
task_queue = None
threads = []
total_urls = 0
processed = [0]
total_lock = threading.Lock()

# === Ctrl+C SEGURO ===
def def_handler(sig, frame):
    print(f"\n\n{RED}[!]{RESET} {YELLOW}Interrumpiendo...{RESET}")
    stop_event.set()
    print(f"{GREEN}[OK] Deteniendo hilos...{RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

# === BANNER ===
def banner():
    print(f"""{CYAN}╔═══════════════════════════════════════════════════════════╗{RESET}
{BOLD}{CYAN}║                  OSINT URL Checker v5.0                   ║{RESET}
{CYAN}║     Verifica URLs activas + Parámetros inyectables        ║{RESET}
{CYAN}╚═══════════════════════════════════════════════════════════╝{RESET}
{RED}                                                    by Frib1t{RESET}""")

# === PARÁMETROS VULNERABLES === Editar el gusto ==========
'''
VULN_PARAMS = [
    "id", "q", "search", "upload", "query", "page", "user", "username", "email", "uploads",
    "cat", "category", "dir", "file", "download", "path", "url", "redirect", "next", "downloads",
    "action", "do", "cmd", "exec", "command", "load", "include", "view", ".git", "commands",
    "module", "lang", "language", "ref", "return", "back", "to", "go", "?"
]

def has_vuln_params(url):
    # Normalizamos todo a minúsculas para búsquedas sencillas
    full_url = url.lower()
    parsed = urlparse(url)

    # 1) Si la URL contiene cualquiera de las palabras clave "vulnerables"
    #    en cualquier parte (path, query, etc.), la marcamos.
    for vuln in VULN_PARAMS:
        if vuln.lower() in full_url:
            return True

    # 2) Si tiene pinta de llevar parámetros o asignaciones:
    #    - cualquier "?" (query string)
    #    - cualquier "=" (asignación tipo a=b incluso en path raro)
    #    - combinación "?=" por si acaso
    if "?" in full_url or "=" in full_url or "?=" in full_url:
        return True

    # Si no cumple nada de lo anterior, no la consideramos "interesante"
    return False

'''
# Keywords que deben coincidir como PALABRA COMPLETA
VULN_PARAMS = [
    "id", "q", "search", "upload", "query", "page", "user", "username",
    "email", "uploads", "cat", "category", "dir", "file", "download",
    "path", "url", "redirect", "next", "downloads", "action", "do", "cmd",
    "exec", "command", "load", "include", "view", "module", "lang",
    "language", "ref", "return", "back", "to", "go"
]

# Rutas sensibles
SENSITIVE_PATHS = [
    # --- Administración ---
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/dashboard", "/dashboard/",
    "/panel", "/panel/", "/cpanel", "/cpanel/", "/login", "/login/", "/auth", "/auth/",

    # --- Ficheros y repositorios ---
    "/.git/", "/.svn/", "/.hg/", "/.idea/", "/.vscode/", "/.env", "/env", "/config/", "/configs/",

    # --- Backups ---
    "/backup/", "/backups/", "/backup.zip", "/backup.tar", "/db_backup",
    "/old/", "/old_site/", "/test/", "/testing/", "/dev/", "/stage/", "/staging/",

    # --- Subidas / Descargas ---
    "/uploads/", "/upload/", "/downloads/", "/download/", "/files/", "/file/",
    "/media/", "/static/",

    # --- Usuarios ---
    "/user/", "/users/", "/account/", "/accounts/", "/profile/", "/profiles/",
    "/member/", "/members/", "/clients/", "/client/",

    # --- Ficheros conocidos peligrosos ---
    "/phpinfo", "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/crossdomain.xml", "/robots.txt", "/sitemap.xml",

    # --- Paneles ocultos ---
    "/adminpanel/", "/admin_area/", "/secret/", "/hidden/", "/private/", "/internal/",

    # --- APIs ---
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/", "/json", "/rpc/",

    # --- Configuración crítica ---
    "/config.php", "/wp-config.php", "/config.json", "/settings", "/settings.php",
    "/database/", "/db/", "/sql/", "/mysql/",

    # --- Lenguajes y frameworks ---
    "/debug", "/debug/", "/django-admin", "/laravel", "/laravel/", "/symfony",
    "/phpmyadmin", "/phpMyAdmin", "/pma/", "/manager/", "/jupyter/", "/notebook/",

    # --- Logs expuestos ---
    "/logs/", "/log/", "/error.log", "/access.log",

    # --- Rutas de LFI típicas ---
    "/etc/passwd", "/etc/shadow", "/proc/self/environ",

    # --- Otras rutas jugosas ---
    "/shell", "/shell.php", "/cmd.php", "/exec.php",
    "/temp/", "/tmp/", "/cache/", "/session/", "/sessions/"
]

def has_vuln_params(url):
    parsed = urlparse(url)
    full_url = url.lower()

    # 1) Path sospechoso (pero solo si coincide exacto, no por subcadenas normales)
    for sensitive in SENSITIVE_PATHS:
        if sensitive in full_url:
            return True

    # 2) Query con parámetros
    qs = parse_qs(parsed.query)
    param_names = [p.lower() for p in qs.keys()]

    # Coincidencia EXACTA (no subcadena)
    if any(p in VULN_PARAMS for p in param_names):
        return True

    # 3) Si hay parámetros aunque no estén en la lista
    if parsed.query:
        return True

    # 4) Si hay "=" en la URL (esto detecta parámetros sin clave o asignaciones raras)
    if "=" in full_url:
        return True

    # 5) Si existe "?" aunque esté vacío
    if "?" in full_url:
        return True

    return False
    
# === VERIFICAR URL ===
def check_url(url, session, results_queue, vuln_queue):
    if stop_event.is_set() or not url.startswith("http"):
        return
    try:
        r = session.head(url, timeout=7, allow_redirects=True)
        if r.status_code in [200, 301, 302, 303, 307, 308]:
            results_queue.put(url)
            if has_vuln_params(url):
                vuln_queue.put(url)
            return
    except:
        pass
    try:
        if stop_event.is_set():
            return
        r = session.get(url, timeout=7, allow_redirects=True)
        if r.status_code in [200, 301, 302, 303, 307, 308]:
            results_queue.put(url)
            if has_vuln_params(url):
                vuln_queue.put(url)
    except:
        pass

# === HILO TRABAJADOR ===
def worker(task_queue, session, results_queue, vuln_queue, p_main):
    while not stop_event.is_set():
        try:
            url = task_queue.get(timeout=1)
        except queue.Empty:
            continue
        if stop_event.is_set():
            task_queue.task_done()
            break
        check_url(url, session, results_queue, vuln_queue)
        with total_lock:
            processed[0] += 1
            p_main.status(f"{processed[0]}/{total_urls} verificadas")
        task_queue.task_done()

# === MAIN ===
def main():
    global task_queue, threads, total_urls
    banner()

    urls = []

    # === LEER URLs ===
    if args.input:
        if args.input in ["-", "stdin"]:
            log.info("Leyendo desde stdin...")
            urls = [line.strip() for line in sys.stdin if line.strip()]
        else:
            if not os.path.isfile(args.input):
                log.failure(f"Archivo no encontrado: {args.input}")
                sys.exit(1)
            with open(args.input, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
    else:
        log.failure("Usa -i o pipe")
        parser.print_help()
        sys.exit(1)

    if not urls:
        log.failure("No hay URLs válidas")
        sys.exit(1)

    total_urls = len(urls)
    processed[0] = 0

    active_file = args.output
    vuln_file = args.vuln_output

    # === COLAS ===
    task_queue = queue.Queue()
    results_queue = queue.Queue()
    vuln_queue = queue.Queue()

    for url in urls:
        task_queue.put(url)

    # === BARRAS ===
    p_main = log.progress("Verificando URLs")
    p_active = log.progress("Activas")
    p_vuln = log.progress("Con parámetros")
    p_main.status(f"0/{total_urls}")
    p_active.status("0")
    p_vuln.status("0")

    # === HILOS ===
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    threads.clear()
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(task_queue, session, results_queue, vuln_queue, p_main))
        t.daemon = True
        t.start()
        threads.append(t)

    # === ESPERAR CON TIMEOUT ===
    while not stop_event.is_set() and processed[0] < total_urls:
        time.sleep(0.1)

    # === FORZAR FINAL ===
    stop_event.set()
    task_queue.join()

    # === GUARDAR ===
    active_count = 0
    vuln_count = 0
    seen_vuln = set()

    with open(active_file, "w", encoding="utf-8") as f_active:
        while not results_queue.empty():
            url = results_queue.get()
            f_active.write(url + "\n")
            active_count += 1

    with open(vuln_file, "w", encoding="utf-8") as f_vuln:
        while not vuln_queue.empty():
            url = vuln_queue.get()
            if url not in seen_vuln:
                f_vuln.write(url + "\n")
                seen_vuln.add(url)
                vuln_count += 1

    # === FINAL ===
    p_main.success(f"Completado: {total_urls} URLs")
    p_active.success(f"{active_count} activas → {active_file}")
    p_vuln.success(f"{vuln_count} con parámetros → {vuln_file}")

# === ARGUMENTOS ===
parser = argparse.ArgumentParser(
    description=f"{CYAN}Verificador OSINT de URLs activas y parámetros inyectables{RESET}",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=f"""
{BOLD}Ejemplos de uso:{RESET}
  {BOLD}cat URLS.txt | python3 active.py{RESET}
  {BOLD}python3 active.py -i URLS.txt -o active.txt{RESET}
  {BOLD}python3 archive.py -u nasa.org | python3 active.py{RESET}
    """
)

parser.add_argument("-i", "--input", help="Archivo o '-' para stdin")
parser.add_argument("-o", "--output", default="active.txt", help="Salida activas")
parser.add_argument("--vuln-output", default="vulnerable_params.txt", help="Salida vulnerables")
parser.add_argument("-t", "--threads", type=int, default=30, help="Hilos")
parser.add_argument("--timeout", type=int, default=7, help="Timeout")
parser.add_argument("--no-color", action="store_true", help="Sin colores")

# === EJECUCIÓN ===
if __name__ == "__main__":
    args = parser.parse_args()
    if args.no_color:
        log.setLevel("ERROR")
    try:
        main()
    except Exception as e:
        log.failure(f"Error: {e}")
        sys.exit(1)
