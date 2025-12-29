import shodan
import socket
import urllib.parse
import os
import time

# === CREDENCIALES ===
SHODAN_API_KEY = "iOPBaHwvZWxXzvuwagvGnb0i1vidaf2s"
api = shodan.Shodan(SHODAN_API_KEY)

# === DICCIONARIOS DE ALTO VALOR ===
KEYWORDS_FINANCIERAS = ["wallet", "private_key", "seed", "credit_card", "cvv", "stripe_key", "payout"]
# Extensiones que forzaremos en las búsquedas de nube
EXT_DOCS = "ext:xlsx OR ext:csv OR ext:sql OR ext:bak OR ext:env"

def live_check(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        res = s.connect_ex((ip, int(port)))
        s.close()
        return res == 0
    except: return False

# === MÓDULO 1: GENERADOR DE PANEL HTML (Google + MEGA + S3) ===
def build_titan_panel():
    print("[+] Construyendo panel v8.0 con extensiones críticas...")
    filename = "panel_titan_v8.html"
    
    # Dorks ultra-específicos para encontrar archivos Excel/SQL con datos sensibles
    dorks = {
        "MEGA: Excel Financieros (CC/PII)": f'site:mega.nz ({EXT_DOCS}) "card number" OR "cvv" OR "billing"',
        "MEGA: Bases de Datos y Backups": f'site:mega.nz ({EXT_DOCS}) "INSERT INTO" OR "wp_users" OR "config"',
        "MEGA: Wallets y Cryptokeys": 'site:mega.nz "wallet.dat" OR "seed phrase" OR "mnemonic"',
        "S3/Google: Excel Tarjetas/Pagos": f'site:s3.amazonaws.com OR site:storage.googleapis.com ({EXT_DOCS}) "card_number" OR "exp_date"',
        "GitHub: API Keys y Logins": 'site:github.com "DB_PASSWORD" OR "STRIPE_SK" ext:env OR ext:conf',
        "Servidores: Directorios Expuestos": 'intitle:"index of" "users.xlsx" OR "orders.csv" OR "backup.sql"'
    }

    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Zenith Titan v8.0</title>")
        f.write("<style>body{background:#000000; color:#00ff41; font-family:monospace; padding:40px;}")
        f.write(".card{background:#0d1117; border:1px solid #238636; padding:20px; margin-bottom:15px; border-radius:8px;}")
        f.write("a{color:#ff79c6; text-decoration:none; font-weight:bold;} a:hover{color:#bd93f9; text-decoration:underline;}")
        f.write("code{color:#8be9fd; background:#1c1c1c; padding:4px; border-radius:4px; display:block; margin-top:10px; font-size:0.9em;}</style></head><body>")
        f.write("<h1>💎 Zenith Titan v8.0: Ultimate Deep Hunter</h1>")
        f.write("<p style='color:#8b949e;'>Escaneo masivo de MEGA, AWS, Google Cloud y Servidores para Bug Bounty.</p><br>")
        
        for titulo, dork in dorks.items():
            link = f"https://www.google.com/search?q={urllib.parse.quote(dork)}"
            f.write(f"<div class='card'><h3>🚀 {titulo}</h3>")
            f.write(f"<code>{dork}</code><br>")
            f.write(f"<a href='{link}' target='_blank'>[ EJECUTAR EN GOOGLE ]</a></div>")
        
        f.write("</body></html>")
    print(f"✅ Panel HTML v8.0 generado con éxito: {filename}")

# === MÓDULO 2: ESCÁNER DE INFRAESTRUCTURA (Shodan) ===
def deep_shodan_scan():
    print("\n[+] Iniciando Escáner de Shodan para IPs Vivas...")
    queries = [
        'product:"MongoDB" -authentication',
        'port:21 "index of" "xlsx" OR "csv" "billing"',
        'http.title:"Login" "Banking" OR "Finance"',
        '"sk_live_" OR "access_key"'
    ]

    log_name = "hallazgos_confirmados.txt"
    
    for q in queries:
        try:
            results = api.search(q, limit=20)
            with open(log_name, "a") as log:
                for match in results['matches']:
                    ip = match['ip_str']
                    port = match['port']
                    data = match.get('data', '').lower()
                    
                    if live_check(ip, port):
                        detecciones = [w for w in KEYWORDS_FINANCIERAS if w in data]
                        if detecciones:
                            print(f"    [🔥] CRÍTICO: {ip}:{port} -> {detecciones}")
                            log.write(f"IP: {ip}:{port} | DETECTADO: {detecciones} | ORG: {match.get('org', 'N/A')}\n")
            time.sleep(1)
        except Exception as e: print(f"    [!] Error: {e}")

if __name__ == "__main__":
    os.system("clear")
    print("==================================================")
    print("   ZENITH TITAN v8.0 - FULL CLOUD & MEGA SCANNER  ")
    print("==================================================")
    
    if SHODAN_API_KEY == "TU_API_KEY_AQUI":
        print("❌ ERROR: Necesitas poner tu API KEY de Shodan.")
    else:
        build_titan_panel()
        deep_shodan_scan()
        print("\n[✓] Auditoría Terminada.")
        print("[*] Revisa 'hallazgos_confirmados.txt' y abre 'panel_titan_v8.html'.")
