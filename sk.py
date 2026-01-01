import shodan
import netlas
import requests
import os
import time
from datetime import datetime, timedelta

# === CONFIGURACIÓN DE LLAVES ===
SHODAN_API_KEY = "iOPBaHwvZWxXzvuwagvGnb0i1vidaf2s"
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = "6280594821"

# === FILTROS GEOGRÁFICOS Y DE TIEMPO ===
PAIS = "MX"  # Cambia por el código de tu país (MX, ES, AR, CO, US, etc.)
DIAS_ATRAS = 30
fecha_limite = (datetime.now() - timedelta(days=DIAS_ATRAS)).strftime('%Y-%m-%d')

# === QUERIES ACTUALIZADAS (CON FILTRO DE PAÍS) ===
# Shodan usa 'country:XX'
QUERIES_SHODAN = {
    "DB_ABIERTAS_LOCAL": f'country:{PAIS} port:27017 -auth',
    "PAGOS_EXPOSICION": f'country:{PAIS} "sk_live_" OR "client_secret"',
    "RANSOMWARE_ALERTA": f'country:{PAIS} "README_FOR_DECRYPT" OR "YOUR_FILES_ARE_ENCRYPTED"'
}

# Netlas usa 'country:XX' y permite filtrar por fecha de recolección
QUERIES_NETLAS = {
    "EXCEL_FINANCIERO": f"country:{PAIS} AND http.body:\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\" AND last_updated:>{fecha_limite}",
    "BASES_CON_DATOS": f"country:{PAIS} AND protocol:mongodb AND responses.body:email AND NOT auth:true",
    "BACKUPS_RECIENTES": f"country:{PAIS} AND http.title:\"Index of\" AND (http.body:\".sql\" OR http.body:\".zip\")"
}

def enviar_telegram(archivo, comentario):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
    if os.path.exists(archivo) and os.path.getsize(archivo) > 0:
        try:
            with open(archivo, 'rb') as f:
                requests.post(url, files={'document': f}, data={'chat_id': TELEGRAM_CHAT_ID, 'caption': comentario})
        except Exception as e: print(f"Error enviando {archivo}: {e}")

def motor_shodan():
    print(f"[+] Shodan: Escaneando {PAIS}...")
    api = shodan.Shodan(SHODAN_API_KEY)
    reporte = f"shodan_{PAIS}.txt"
    with open(reporte, "w") as f:
        for cat, q in QUERIES_SHODAN.items():
            try:
                results = api.search(q, limit=15)
                f.write(f"\n=== {cat} ===\n")
                for res in results['matches']:
                    f.write(f"IP: {res['ip_str']}:{res['port']} | ISP: {res.get('isp', 'N/A')}\n")
                time.sleep(1)
            except: pass
    return reporte

def motor_netlas():
    print(f"[+] Netlas: Escaneando {PAIS} (Últimos {DIAS_ATRAS} días)...")
    n_api = netlas.Netlas(api_key=NETLAS_API_KEY)
    reporte = f"netlas_{PAIS}.txt"
    with open(reporte, "w") as f:
        for cat, q in QUERIES_NETLAS.items():
            try:
                results = n_api.query(query=q, datatype='response')
                f.write(f"\n=== {cat} ===\n")
                for item in results['items']:
                    f.write(f"IP: {item['data']['ip']}:{item['data']['port']} | Dominio: {item['data'].get('domain', 'N/A')}\n")
            except: pass
    return reporte

if __name__ == "__main__":
    os.system("clear")
    print(f"🛰️ ZENITH TITAN v14.0 | FILTRO: {PAIS} | DESDE: {fecha_limite}")
    
    if "TU_API" in SHODAN_API_KEY or "TU_API" in NETLAS_API_KEY:
        print("❌ Configura tus llaves API primero.")
    else:
        # Ejecutar y enviar
        r_shodan = motor_shodan()
        enviar_telegram(r_shodan, f"📍 Infraestructura en {PAIS} (Shodan)")
        
        r_netlas = motor_netlas()
        enviar_telegram(r_netlas, f"📂 Archivos y Datos en {PAIS} (Netlas)")
        
        print("\n[✓] Escaneo Geográfico completado. Revisa Telegram.")
