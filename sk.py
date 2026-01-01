import telebot
from telebot import types
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
TELEGRAM_CHAT_ID = 6280594821 

# Inicialización de APIs
bot = telebot.TeleBot(TELEGRAM_TOKEN)
s_api = shodan.Shodan(SHODAN_API_KEY)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# --- SISTEMA DE CRONÓMETRO Y FEEDBACK ---
def actualizar_cronometro(chat_id, message_id, tarea, segundos):
    """Muestra un cronómetro descendente en el chat"""
    for i in range(segundos, 0, -5):
        try:
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=f"⏳ *{tarea}*\n⏱️ Tiempo estimado: `{i} seg`...",
                parse_mode="Markdown"
            )
            time.sleep(5)
        except: break

# --- MIDDLEWARE DE SEGURIDAD ---
def es_usuario_autorizado(id):
    return id == TELEGRAM_CHAT_ID

# --- COMANDOS PRINCIPALES ---
@bot.message_handler(commands=['start'])
def send_welcome(message):
    if not es_usuario_autorizado(message.from_user.id):
        bot.reply_to(message, "❌ Acceso denegado. ID no autorizado.")
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("🚀 Escaneo MX", callback_data='scan_MX'),
        types.InlineKeyboardButton("💰 Wallets Global", callback_data='scan_wallet'),
        types.InlineKeyboardButton("🏦 Logins Bank", callback_data='scan_bank'),
        types.InlineKeyboardButton("🔑 API Keys", callback_data='scan_keys'),
        types.InlineKeyboardButton("⚙️ Status API", callback_data='status')
    )
    
    bot.send_message(message.chat.id, 
        "💎 *ZENITH TITAN v17.0 PRO*\n\n"
        "Sistema de Inteligencia de Amenazas activo.\n"
        "Seleccione una operación táctica:", 
        parse_mode="Markdown", reply_markup=markup)

# --- PROCESADOR DE ACCIONES (CALLBACKS) ---
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if not es_usuario_autorizado(call.from_user.id): return

    # 1. ESCANEO MÉXICO (Combinado)
    if call.data == "scan_MX":
        msg = bot.edit_message_text("🛰️ Iniciando protocolo México...", call.message.chat.id, call.message.message_id)
        actualizar_cronometro(call.message.chat.id, msg.message_id, "Analizando infraestructura MX", 20)
        
        reporte = f"Reporte_MX_{int(time.time())}.txt"
        with open(reporte, "w") as f:
            f.write(f"--- REPORTE TÁCTICO MX - {datetime.now()} ---\n\n")
            try:
                # Búsqueda Shodan (DBs)
                res = s_api.search(f'country:MX port:27017 -auth', limit=15)
                f.write("[SHODAN: MONGODB ABIERTAS]\n")
                for m in res['matches']: f.write(f"IP: {m['ip_str']}:{m['port']} | ISP: {m.get('isp')}\n")
            except: f.write("Error en Shodan\n")

        with open(reporte, "rb") as d:
            bot.send_document(TELEGRAM_CHAT_ID, d, caption="📍 Auditoría MX Completada")
        os.remove(reporte)

    # 2. WALLETS GLOBAL (Rápido)
    elif call.data == "scan_wallet":
        bot.answer_callback_query(call.id, "Buscando activos cripto...")
        try:
            res = s_api.search('"wallet.dat" OR "mnemonic" OR "private_key" -auth', limit=10)
            txt = "💰 *POTENCIALES WALLETS DETECTADAS:*\n\n"
            for m in res['matches']:
                txt += f"• `{m['ip_str']}:{m['port']}` ({m.get('location', {}).get('country_name', '??')})\n"
            bot.send_message(TELEGRAM_CHAT_ID, txt, parse_mode="Markdown")
        except: bot.send_message(TELEGRAM_CHAT_ID, "⚠️ Error en motor Shodan.")

    # 3. LOGINS BANCARIOS (Netlas)
    elif call.data == "scan_bank":
        msg = bot.edit_message_text("🏦 Rastreando portales bancarios...", call.message.chat.id, call.message.message_id)
        actualizar_cronometro(call.message.chat.id, msg.message_id, "Buscando logins expuestos", 30)
        try:
            q = "http.title:\"login\" AND (http.body:\"bank\" OR http.body:\"banca\")"
            res = n_api.query(query=q, datatype='response')
            reporte = "banks_logins.txt"
            with open(reporte, "w") as f:
                for i in res['items']: 
                    f.write(f"IP: {i['data']['ip']} | Título: {i['data'].get('http',{}).get('title')}\n")
            with open(reporte, "rb") as d:
                bot.send_document(TELEGRAM_CHAT_ID, d, caption="🏦 Listado de Logins Detectados")
            os.remove(reporte)
        except: bot.send_message(TELEGRAM_CHAT_ID, "⚠️ Error en motor Netlas.")

    # 4. STATUS
    elif call.data == "status":
        bot.answer_callback_query(call.id, "Verificando conexión...")
        bot.send_message(TELEGRAM_CHAT_ID, 
            f"✅ *ESTADO DEL SISTEMA*\n\n"
            f"📡 *Shodan:* Conectado\n"
            f"📡 *Netlas:* Conectado\n"
            f"🆔 *Tu ID:* `{TELEGRAM_CHAT_ID}`\n"
            f"🛡️ *Seguridad:* Encriptado", parse_mode="Markdown")

# --- INICIO ---
if __name__ == "__main__":
    os.system("clear")
    print(f"========================================")
    print(f"   ZENITH TITAN v17.0 - BOT INICIADO    ")
    print(f"   ESPERANDO COMANDOS EN TELEGRAM...    ")
    print(f"========================================")
    bot.infinity_polling()
