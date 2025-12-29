import shodan
import socket
import urllib.parse
import os
import time

# === CONFIGURACIÓN GLOBAL ===
# Consigue tu API KEY en https://account.shodan.io
SHODAN_API_KEY = "iOPBaHwvZWxXzvuwagvGnb0i1vidaf2s"
api = shodan.Shodan(SHODAN_API_KEY)

# Palabras clave de alto valor (Finanzas, Leaks, Privacidad)
KEYWORDS = ["wallet", "private_key", "seed phrase", "credit_card", "db_password", "bank_login", "confidential"]

# === MÓDULO 1: VERIFICACIÓN DE CONEXIÓN (PORT SCANNER) ===
def puerto_esta_vivo(ip, puerto):
    """ Verifica si el objetivo sigue activo antes de reportar """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        resultado = sock.connect_ex((ip, int(puerto)))
        sock.close()
        return resultado == 0
    except:
        return False

# === MÓDULO 2: GENERADOR DE CLOUD LEAKS (DORKS) ===
def generar_panel_nube():
    print("[+] Generando Panel de Cloud Dorking...")
    filename = "panel_cloud_hunter.html"
    dorks = {
        "Cloud Wallets": 'site:s3.amazonaws.com OR site:storage.googleapis.com "wallet.dat" OR "keys.json"',
        "Financial Backups": 'site:s3.amazonaws.com OR site:storage.googleapis.com "backup" "sql" "finance"',
        "Login Paneles": 'intitle:"login" "admin" "banking" -github.com'
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><body style='background:#050505; color:#00ff41; font-family:monospace; padding:30px;'>")
        f.write("<h1 style='color:#ff003c;'>🛡️ Cloud & Financial Hunter</h1>")
        for desc, dork in dorks.items():
            link = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
            f.write(f"<div style='margin-bottom:20px;'><strong>[!] {desc}:</strong><br>")
            f.write(f"<a href='{link}' style='color:#0087ff;' target='_blank'>{dork}</a></div>")
        f.write("</body></html>")
    print(f"[*] Panel HTML listo en: {filename}")

# === MÓDULO 3: ESCÁNER DE INFRAESTRUCTURA (SHODAN) ===
def escanear_infraestructura():
    print("\n[+] Iniciando Escáner de Shodan (Buscando activos para aviso)...")
    # Buscamos paneles de administración financieros y bases de datos sin password
    queries = [
        'product:"MongoDB" -authentication',
        'http.title:"Login" "Banking" -port:80,443',
        'http.title:"Dashboard" "Finance" -authentication'
    ]
    
    hallazgos_log = "hallazgos_confirmados.txt"
    
    for q in queries:
        try:
            print(f"    > Ejecutando Query: {q}")
            results = api.search(q, limit=15)
            
            with open(hallazgos_log, "a") as log:
                for result in results['matches']:
                    ip = result['ip_str']
                    port = result['port']
                    org = result.get('org', 'Desconocida')
                    banner = result.get('data', '').lower()
                    
                    if puerto_esta_vivo(ip, port):
                        print(f"    [⚠️] LIVE: {ip}:{port} | Org: {org}")
                        # Detectar palabras clave en el banner del servidor
                        matches = [k for k in KEYWORDS if k in banner]
                        if matches:
                            print(f"        🚨 CONTENIDO SENSIBLE: {matches}")
                            log.write(f"IP: {ip}:{port} | Org: {org} | Detectado: {matches}\n")
            time.sleep(1) # Delay para evitar baneo de API
        except Exception as e:
            print(f"    [!] Error en Query: {e}")

# === FLUJO PRINCIPAL ===
if __name__ == "__main__":
    os.system("clear")
    print("==============================================")
    print("   ZENITH HUNTER PRO - CIBERSEGURIDAD ÉTICA   ")
    print("==============================================")
    
    if SHODAN_API_KEY == "TU_API_KEY_AQUI":
        print("[X] ERROR: Debes insertar tu API Key de Shodan en el código.")
    else:
        generar_panel_nube()
        escanear_infraestructura()
        print("\n[✓] Auditoría Finalizada.")
        print("[!] Revisa 'hallazgos_confirmados.txt' para ver las IPs vivas.")
        print("[!] Usa 'termux-open panel_cloud_hunter.html' para auditoría en nube.")
