#!/usr/bin/env python3
"""
Simple Port Scanner v2 (Hersec Labs)

Mejoras:
- Parseo de rangos y listas de puertos (1-1024, 22,80,443)
- Concurrency con ThreadPoolExecutor
- Resolución de hostname a IP
- Opción de exportar resultados a CSV
- Mensajes claros y uso responsable

Uso (ejemplos):
    python simple_port_scanner_v2.py -t example.com -p 1-1024
    python simple_port_scanner_v2.py -t 192.168.0.10 -p 22,80,443 --csv report.csv
"""

import socket
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import csv

try:
    from termcolor import colored
except Exception:
    # Fallback si no está instalado termcolor
    def colored(text, color=None):
        return text

# -- configuración
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 200

# estado global simple para permitir cierre ordenado
stop_scanning = False

def signal_handler(sig, frame):
    global stop_scanning
    print(colored("\n[!] Interrupción recibida — deteniendo escaneo...", "red"))
    stop_scanning = True

signal.signal(signal.SIGINT, signal_handler)


def parse_ports(ports_str):
    """
    Acepta formatos:
    - rango: 1-1024
    - lista: 22,80,443
    - mixto: 1-100,443,8080
    Devuelve una lista ordenada y sin duplicados.
    """
    ports = set()
    parts = [p.strip() for p in ports_str.split(',') if p.strip()]
    for part in parts:
        if '-' in part:
            try:
                a, b = map(int, part.split('-', 1))
                if a > b:
                    a, b = b, a
                ports.update(range(max(1, a), min(65535, b) + 1))
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    return sorted(ports)


def scan_port(host_ip, port, timeout=DEFAULT_TIMEOUT):
    """
    Intenta conexión TCP al puerto. Devuelve (port, True/False, banner_or_err)
    """
    if stop_scanning:
        return port, False, "stopped"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host_ip, port))
        # try to read a small banner (best-effort)
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024)
            try:
                banner = banner.decode(errors='ignore').strip()
            except Exception:
                banner = repr(banner)
        except Exception:
            banner = ""
        s.close()
        return port, True, banner or "open"
    except (socket.timeout, ConnectionRefusedError):
        return port, False, ""
    except Exception as e:
        return port, False, f"error:{e}"


def resolve_target(target):
    """Resuelve hostname a IP (si es necesario)."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except Exception as e:
        raise RuntimeError(f"No se pudo resolver '{target}': {e}")


def run_scan(target, ports, workers=MAX_WORKERS, timeout=DEFAULT_TIMEOUT):
    host_ip = resolve_target(target)
    start = datetime.now()
    print(colored(f"[+] Escaneando {target} ({host_ip}) — {len(ports)} puertos", "cyan"))
    results = []

    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as executor:
        futures = {executor.submit(scan_port, host_ip, p, timeout): p for p in ports}
        try:
            for fut in as_completed(futures):
                p = futures[fut]
                port, is_open, info = fut.result()
                if is_open:
                    print(colored(f"[+] Puerto {port} abierto — {info}", "green"))
                # opcional: print para puertos cerrados (comenta si querés menos ruido)
                # else:
                #     print(colored(f"[-] Puerto {port} cerrado", "grey"))
                results.append((port, is_open, info))
                if stop_scanning:
                    break
        except KeyboardInterrupt:
            print(colored("\n[!] Escaneo interrumpido por usuario", "red"))

    end = datetime.now()
    print(colored(f"[+] Escaneo finalizado en {str(end - start)}", "cyan"))
    return host_ip, results, start, end


def export_csv(path, target, host_ip, results, start, end):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['target', target])
        writer.writerow(['host_ip', host_ip])
        writer.writerow(['start', start.isoformat()])
        writer.writerow(['end', end.isoformat()])
        writer.writerow([])
        writer.writerow(['port', 'open', 'info'])
        for port, is_open, info in sorted(results, key=lambda x: x[0]):
            writer.writerow([port, "yes" if is_open else "no", info])
    print(colored(f"[+] Reporte exportado a {path}", "cyan"))


def get_args():
    parser = argparse.ArgumentParser(description="Simple Port Scanner v2 - Hersec Labs (uso responsable)")
    parser.add_argument("-t", "--target", required=True, help="Host o IP a escanear (ej: -t example.com)")
    parser.add_argument("-p", "--ports", required=True, help="Rango/lista de puertos (ej: -p 1-1024 o -p 22,80,443 o mixto)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout por socket (segundos)")
    parser.add_argument("--workers", type=int, default=100, help="Número de hilos concurrentes")
    parser.add_argument("--csv", help="Exportar resultados a CSV (ruta de archivo)")
    parser.add_argument("--quiet", action="store_true", help="Minimizar salida (solo puertos abiertos)")
    return parser.parse_args()


def main():
    args = get_args()
    try:
        ports = parse_ports(args.ports)
        if not ports:
            print(colored("[!] No se detectaron puertos válidos en el parámetro --ports", "red"))
            sys.exit(1)
        host_ip, results, start, end = run_scan(args.target, ports, workers=args.workers, timeout=args.timeout)
        if args.csv:
            export_csv(args.csv, args.target, host_ip, results, start, end)
    except RuntimeError as e:
        print(colored(f"[!] Error: {e}", "red"))
        sys.exit(2)


if __name__ == "__main__":
    main()
