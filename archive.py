#!/usr/bin/env python3
"""
OSINT Wayback URL Collector v4.0 - BANNER PERFECTO
"""

import requests
import time
import sys
import argparse
import os
from pwn import *

# === COLORES ===
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"

# === BANNER FIJO Y ALINEADO ===
def banner():
    print(f"""{CYAN}╔═══════════════════════════════════════════════════════════╗{RESET}""")
    print(f"""{BOLD}{CYAN}║          OSINT Wayback URL Collector v4.0                 ║{RESET}""")
    print(f"""{CYAN}║      URLs históricas by Frib1t                            ║{RESET}""")
    print(f"""{CYAN}╚═══════════════════════════════════════════════════════════╝{RESET}""")


# === WAYBACK URLs ===
def get_wayback_urls(domain, session, p_urls):
    params = {
        "url": f"{domain}/*",
        "output": "text",
        "fl": "original",
        "collapse": "urlkey"
    }
    for attempt in range(1, args.max_retry + 1):
        try:
            if attempt > 1:
                log.wait(f"Reintentando {domain} ({attempt}/{args.max_retry})")
                time.sleep(args.sleep)
            r = session.get(args.wayback_url, params=params, timeout=15)
            if r.status_code == 200 and r.text.strip():
                urls = [line.strip() for line in r.text.splitlines() if line.strip()]
                p_urls.status(f"{len(urls)} URLs")
                return urls
        except Exception as e:
            log.warn(f"Error en {domain}: {e}")
            time.sleep(args.sleep)
    return []

# === GUARDAR URLs ===
def save_urls(urls, output_file):
    with open(output_file, "a", encoding="utf-8") as f:
        for url in urls:
            f.write(url + "\n")

# === MAIN ===
def main():
    banner()

    domains = []

    if args.url:
        domains = [args.url.strip()]
    elif args.input:
        if args.input in ["-", "stdin"]:
            log.info("Leyendo desde stdin...")
            domains = [line.strip() for line in sys.stdin if line.strip() and not line.startswith("#")]
        else:
            if not os.path.isfile(args.input):
                log.failure(f"Archivo no encontrado: {args.input}")
                sys.exit(1)
            with open(args.input, "r", encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        log.failure("Usa -u, -i o pipe")
        parser.print_help()
        sys.exit(1)

    if not domains:
        log.failure("No hay dominios válidos")
        sys.exit(1)

    total = len(domains)
    url_counter = 0
    session = requests.Session()

    p_main = log.progress("Recolectando")
    p_urls = log.progress("URLs encontradas")
    p_main.status(f"0/{total}")
    p_urls.status("0")

    for idx, domain in enumerate(domains, 1):
        p_main.status(f"{idx}/{total} → {domain}")
        urls = get_wayback_urls(domain, session, p_urls)

        if urls:
            unique_urls = sorted(set(urls))
            save_urls(unique_urls, args.output)
            url_counter += len(unique_urls)
            p_urls.status(f"{url_counter}")
        else:
            p_urls.status(f"{url_counter} (sin resultados)")

        if idx < total:
            time.sleep(args.sleep)

    p_main.success(f"Completado: {total} dominios")
    p_urls.success(f"Total: {url_counter} URLs → {args.output}")

# === ARGUMENTOS ===
parser = argparse.ArgumentParser(
    description=f"{CYAN}Recolector OSINT con barra de progreso{RESET}",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=f"""
{BOLD}Ejemplos de uso:{RESET}
  {BOLD}python3 archive.py -u nasa.org{RESET}
  {BOLD}python3 archive.py -u nasa.org -o urls.txt{RESET}
  {BOLD}python3 archive.py -i subs.txt{RESET}
  {BOLD}python3 archive.py -i subs.txt -o urls.txt --sleep 5{RESET}
  {BOLD}cat subs.txt | python3 archive.py{RESET}
  {BOLD}echo "nasa.org" | python3 archive.py -o nasa.txt{RESET}
    """
)

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-u", "--url", help="Un solo dominio")
group.add_argument("-i", "--input", help="Archivo o '-' para stdin")

parser.add_argument("-o", "--output", default="URLS.txt", help="Archivo de salida")
parser.add_argument("--wayback-url", default="https://web.archive.org/cdx/search/cdx", help="URL CDX")
parser.add_argument("--sleep", type=int, default=15, help="Segundos entre consultas")
parser.add_argument("--max-retry", type=int, default=3, help="Reintentos")
parser.add_argument("--no-color", action="store_true", help="Sin colores")

# === EJECUCIÓN ===
if __name__ == "__main__":
    args = parser.parse_args()
    if args.no_color:
        log.console.quiet = True
    try:
        main()
    except KeyboardInterrupt:
        log.warn("\nInterrumpido por el usuario.")
        sys.exit(1)
