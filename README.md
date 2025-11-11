# Simple Port Scanner v2 (Hersec Labs)

# Escanear puertos 1-1024 en example.com
python simple_port_scanner_v2.py -t example.com -p 1-1024

# Escanear algunos puertos y exportar reporte
python simple_port_scanner_v2.py -t 192.168.0.10 -p 22,80,443 --csv report.csv

# Escanear con menor timeout y más workers
python simple_port_scanner_v2.py -t 10.0.0.5 -p 1-500 --timeout 0.5 --workers 200


Herramienta educativa para escaneo TCP rápido y auditoría básica en redes.  
**Uso responsable:** solo utilice esta herramienta en equipos y redes que usted posea o tenga permiso para auditar.

## Características
- Parseo de puertos: rangos (`1-1024`), listas (`22,80,443`) o mixto.
- Resolución de hostnames a IP.
- Concurrency con `ThreadPoolExecutor`.
- Opción de exportar reporte a CSV.
- Tiempo total del escaneo mostrado.
- Uso didáctico y compatible con prácticas de pentesting responsable.

## Requisitos
- Python 3.8+
- (Opcional) termcolor para colores:
```bash
pip install termcolor
