import netlas
import shodan
import urllib.parse
import os
import time

# === CONFIGURACIÓN DE LLAVES ===
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
SHODAN_API_KEY = "iOPBaHwvZWxXzvuwagvGnb0i1vidaf2s"

def hunter_netlas_wallets():
    print("\n[+] 🔎 Iniciando Rastreo Automatizado en Netlas (Buscando Wallets)...")
    try:
        n_api = netlas.Netlas(api_key=NETLAS_API_KEY)
        
        # Query potente: Busca protocolos de base de datos que mencionen 'wallet' en su estructura
        # y que NO requieran autenticación.
        query = "protocol:mongodb AND NOT auth:true AND responses.body:wallet"
        
        # Realizamos la búsqueda
        netlas_results = n_api.query(query=query, datatype='response')
        
        hallazgos = 0
        with open("wallets_netlas_report.txt", "a") as f:
            for item in netlas_results['items']:
                ip = item['data']['ip']
                port = item['data']['port']
                # Extraemos info de la base de datos si está disponible
                body = item['data'].get('body', '')
                
                print(f"    [💰] ¡POSIBLE WALLET DETECTADA!: {ip}:{port}")
                f.write(f"IP: {ip}:{port} | Fuente: Netlas | Query: {query}\n")
                hallazgos += 1
                
        print(f"✅ Se han guardado {hallazgos} posibles objetivos en 'wallets_netlas_report.txt'")
        
    except Exception as e:
        print(f"    [!] Error en Netlas: {e}")

def build_ultimate_panel():
    print("[+] Actualizando Panel Maestro HTML...")
    # Añadimos dorks de Netlas que son mejores que Google para contenido crudo
    dorks = {
        "Netlas: DBs con 'Credit Card'": "https://netlas.io/responses/?q=responses.body%3A%22card_number%22+AND+NOT+auth%3Atrue",
        "Netlas: Archivos .ENV Expuestos": "https://netlas.io/responses/?q=http.body%3A%22STRIPE_SK%22+OR+http.body%3A%22AWS_SECRET%22",
        "MEGA: Backups de Bancos (.sql)": 'site:mega.nz ext:sql "backup" "bank" OR "finance"',
        "FOFA: Paneles de Pago": 'https://fofa.info/result?qbase64=' + urllib.parse.quote('title="payment gateway" || body="checkout"')
    }
    
    filename = "panel_titan_v10.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><body style='background:#000; color:#0f0; font-family:monospace; padding:30px;'>")
        f.write("<h1>💎 Zenith Titan v10.0 - Netlas Edition</h1>")
        for titulo, url in dorks.items():
            f.write(f"<div style='border:1px solid #0f0; padding:10px; margin:10px;'>")
            f.write(f"<h3>{titulo}</h3><a href='{url}' style='color:cyan;' target='_blank'>[ INVESTIGAR ]</a></div>")
        f.write("</body></html>")

if __name__ == "__main__":
    os.system("clear")
    print("==================================================")
    print("   ZENITH TITAN v10.0 - THE NETLAS REVOLUTION     ")
    print("==================================================")
    
    build_ultimate_panel()
    if NETLAS_API_KEY != "TU_API_KEY_NETLAS":
        hunter_netlas_wallets()
    else:
        print("[!] Por favor inserta tu API KEY de Netlas para automatizar.")
