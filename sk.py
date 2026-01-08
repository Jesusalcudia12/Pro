import telebot
from telebot import types
import requests
import subprocess
import os
import glob
from urllib.parse import quote

# ==========================================
# CONFIGURACIÓN
# ==========================================
TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
ADMIN_ID = 6280594821 

bot = telebot.TeleBot(TOKEN)
DB_PATH = "database.txt"

# ==========================================
# FUNCIONES DE BÚSQUEDA AVANZADA
# ==========================================

def search_dark_web(target):
    """Genera enlaces de búsqueda para motores de la Dark Web (Tor)"""
    query = quote(f'"{target}" password leak 2026')
    # Motores especializados en la Deep/Dark Web (vía proxies web)
    return f"🕵️ **Deep Search:** [Resultados de Dark Web](https://ahmia.fi/search/?q={query})"

def search_scribd(target):
    """Busca documentos filtrados en Scribd"""
    query = quote(f'site:scribd.com "{target}" password filetype:txt OR filetype:pdf')
    return f"📄 **Scribd:** [Documentos Filtrados](https://www.google.com/search?q={query})"

# ==========================================
# MANEJADORES DE COMANDOS
# ==========================================

@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.chat.id != ADMIN_ID: return
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=3)
    markup.add('/logins', '/dark_search', '/scan', '/exploit', '/find_bugs', '/scan_url', '/upload_combo', '/status', '/help')
    bot.send_message(message.chat.id, "💎 **ZENITH TITAN v76.0**\nScribd & Dark Web Engines: **ACTIVOS**", reply_markup=markup)

@bot.message_handler(commands=['help'])
def cmd_help(message):
    bot.send_message(message.chat.id, "📖 **Zenith Titan Guide:**\nUse el botón 'Menú' para ver la lista completa de comandos de auditoría.")

# --- [logins] Phonebook ---
@bot.message_handler(commands=['logins'])
def cmd_logins(message):
    msg = bot.send_message(message.chat.id, "📧 **Phonebook:** Ingrese dominio o empresa:")
    bot.register_next_step_handler(msg, exec_logins)

def exec_logins(message):
    target = message.text.strip().lower()
    res = f"🔍 **Identidades para {target}:**\n"
    res += f"📍 `admin@{target}`\n📍 `soporte@{target}`\n\n"
    res += f"{search_scribd(target)}" # Incluye búsqueda en Scribd
    bot.send_message(message.chat.id, res, parse_mode="Markdown", disable_web_page_preview=True)

# --- [dark_search] Deep Search ---
@bot.message_handler(commands=['dark_search'])
def cmd_dark(message):
    msg = bot.send_message(message.chat.id, "🔑 **Deep Search:** Ingrese objetivo (email/dominio):")
    bot.register_next_step_handler(msg, exec_dark)

def exec_dark(message):
    target = message.text.strip()
    res = f"💀 **Buscando en la Web Oscura e IntelX...**\n\n"
    res += f"📍 `{target}:P@ssword_Titan_2026` (Simulado)\n\n"
    res += f"{search_dark_web(target)}"
    bot.send_message(message.chat.id, res, parse_mode="Markdown", disable_web_page_preview=True)

# --- [scan] Netlas Mapping ---
@bot.message_handler(commands=['scan'])
def cmd_scan(message):
    msg = bot.send_message(message.chat.id, "🌐 **Netlas:** Ingrese IP o Dominio:")
    bot.register_next_step_handler(msg, exec_netlas)

def exec_netlas(message):
    headers = {"X-API-Key": NETLAS_API_KEY}
    try:
        r = requests.get(f"https://app.netlas.io/api/host/{message.text}/", headers=headers, timeout=10)
        d = r.json()
        bot.send_message(message.chat.id, f"🌐 **Netlas Mapping:**\nIP: `{d.get('ip')}`\nISP: `{d.get('isp')}`\nGeo: `{d.get('country')}`")
    except: bot.send_message(message.chat.id, "❌ Error en Netlas.")

# --- [exploit] CVE Search ---
@bot.message_handler(commands=['exploit'])
def cmd_exploit(message):
    msg = bot.send_message(message.chat.id, "💀 **CVE Search:** Ingrese software:")
    bot.register_next_step_handler(msg, exec_exploit)

def exec_exploit(message):
    try:
        r = requests.get(f"https://cve.circl.lu/api/search/{message.text}", timeout=10)
        data = r.json()[:3]
        res = f"⚠️ **Hallazgos CVE para {message.text}:**\n"
        for i in data: res += f"❌ `{i['id']}`: {i['summary'][:80]}...\n"
        bot.send_message(message.chat.id, res)
    except: bot.send_message(message.chat.id, "❌ Error CVE.")

# --- [find_bugs] Nmap Audit ---
@bot.message_handler(commands=['find_bugs'])
def cmd_nmap(message):
    msg = bot.send_message(message.chat.id, "🎯 **Nmap:** Ingrese IP objetivo:")
    bot.register_next_step_handler(msg, exec_nmap)

def exec_nmap(message):
    try:
        scan = subprocess.check_output(["nmap", "-F", message.text], text=True, timeout=120)
        bot.send_message(message.chat.id, f"```\n{scan[:1000]}\n```", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Error Nmap.")

# --- [scan_url] Local Search ---
@bot.message_handler(commands=['scan_url'])
def cmd_scan_url(message):
    msg = bot.send_message(message.chat.id, "📂 **Local Search:** Palabra clave a buscar en .txt:")
    bot.register_next_step_handler(msg, exec_local)

def exec_local(message):
    query = message.text.strip().lower()
    matches = []
    if os.path.exists(DB_PATH):
        with open(DB_PATH, 'r', errors='ignore') as f:
            for line in f:
                if query in line.lower(): 
                    matches.append(line.strip())
                    if len(matches) > 10: break
    bot.send_message(message.chat.id, "📂 **Resultados:**\n" + ("\n".join(matches) if matches else "❌ Sin resultados."))

# --- [upload_combo] ---
@bot.message_handler(commands=['upload_combo'])
def cmd_upload(message):
    bot.send_message(message.chat.id, "📤 Envíe un archivo .txt para la base de datos.")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    with open(DB_PATH, 'ab') as f: f.write(downloaded)
    bot.send_message(message.chat.id, "✅ Base de datos local actualizada.")

@bot.message_handler(commands=['status'])
def cmd_status(message):
    bot.send_message(message.chat.id, "🟢 **SISTEMA:** ONLINE\n📡 **ENGINE:** v76.0 Titanium")

if __name__ == "__main__":
    bot.infinity_polling()
