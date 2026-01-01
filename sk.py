import telebot
from telebot import types
import shodan
import netlas
import requests
import os
import time
from datetime import datetime, timedelta

# === CONFIGURACIÓN DE LLAVES (Actualizadas) ===
SHODAN_API_KEY = "iOPBaHwvZWxXzvuwagvGnb0i1vidaf2s"
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821  # Tu ID como entero para validación

# Inicialización
bot = telebot.TeleBot(TELEGRAM_TOKEN)
s_api = shodan.Shodan(SHODAN_API_KEY)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# --- MIDDLEWARE DE SEGURIDAD ---
def solo_yo(message):
    return message.from_user.id == TELEGRAM_CHAT_ID

# --- FUNCIONES DE BÚSQUEDA ---
def ejecutar_busqueda_completa(pais="MX"):
    fecha_limite = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    reporte_name = f"Titan_Report_{pais}.txt"
    
    with open(reporte_name, "w") as f:
        f.write(f"=== ZENITH TITAN V15.5 - REPORTE {pais} ===\n")
        f.write(f"Fecha: {datetime.now()}\n\n")
        
        # Shodan Sector
        try:
            q_shodan = f'country:{pais} port:27017 -auth'
            res = s_api.search(q_shodan, limit=10)
            f.write("--- MONGODB EXPUESTAS (SHODAN) ---\n")
            for m in res['matches']:
                f.write(f"IP: {m['ip_str']}:{m['port']} | Org: {m.get('org', 'N/A')}\n")
        except: f.write("Error en Shodan DB\n")
        
        # Netlas Sector
        try:
            q_netlas = f"country:{pais} AND http.body:\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\""
            res_n = n_api.query(query=q_netlas, datatype='response')
            f.write("\n--- EXCEL FINANCIEROS (NETLAS) ---\n")
            for item in res_n['items']:
                f.write(f"IP: {item['data']['ip']} | Host: {item['data'].get('domain', 'N/A')}\n")
        except: f.write("Error en Netlas Files\n")

    return reporte_name

# --- COMANDOS DEL BOT ---
@bot.message_handler(commands=['start'], func=solo_yo)
def send_welcome(message):
    markup = types.InlineKeyboardMarkup(row_width=2)
    btn1 = types.InlineKeyboardButton("🚀 Escaneo MX", callback_data='scan_MX')
    btn2 = types.InlineKeyboardButton("💰 Wallets Global", callback_data='scan_wallet')
    btn3 = types.InlineKeyboardButton("🏦 Logins Bank", callback_data='scan_bank')
    btn4 = types.InlineKeyboardButton("🛠 Status API", callback_data='status')
    markup.add(btn1, btn2, btn3, btn4)
    
    bot.reply_to(message, "💎 *Zenith Titan v15.5 Pro*\nBienvenido Comandante. Seleccione una operación:", 
                 parse_mode="Markdown", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.data == "scan_MX":
        bot.answer_callback_query(call.id, "Iniciando escaneo profundo...")
        file = ejecutar_busqueda_completa("MX")
        with open(file, 'rb') as doc:
            bot.send_document(TELEGRAM_CHAT_ID, doc, caption="📍 Reporte Crítico México")
        os.remove(file)
        
    elif call.data == "scan_wallet":
        bot.answer_callback_query(call.id, "Buscando Private Keys...")
        try:
            res = s_api.search('"wallet.dat" OR "private_key" -auth', limit=15)
            txt = "💰 *WALLETS ENCONTRADAS:*\n\n"
            for m in res['matches']:
                txt += f"• `{m['ip_str']}:{m['port']}`\n"
            bot.send_message(TELEGRAM_CHAT_ID, txt, parse_mode="Markdown")
        except: bot.send_message(TELEGRAM_CHAT_ID, "Error en API")

    elif call.data == "scan_bank":
        bot.answer_callback_query(call.id, "Rastreando Logins...")
        q = "http.title:\"login\" AND (http.body:\"bank\" OR http.body:\"banca\")"
        try:
            res = n_api.query(query=q, datatype='response')
            with open("banks.txt", "w") as f:
                for i in res['items']: f.write(f"IP: {i['data']['ip']} | {i['data'].get('domain', 'N/A')}\n")
            with open("banks.txt", "rb") as d:
                bot.send_document(TELEGRAM_CHAT_ID, d, caption="🏦 Logins Bancarios Detectados")
            os.remove("banks.txt")
        except: bot.send_message(TELEGRAM_CHAT_ID, "Error en Netlas")

    elif call.data == "status":
        bot.send_message(TELEGRAM_CHAT_ID, "✅ APIs Conectadas y Operativas.")

# --- INICIO ---
if __name__ == "__main__":
    os.system("clear")
    print(f"🛰️ ZENITH TITAN BOT ACTIVO\nID Autorizado: {TELEGRAM_CHAT_ID}")
    bot.infinity_polling()
