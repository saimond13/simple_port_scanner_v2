# Simple Port Scanner v2 (Hersec Labs)

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
