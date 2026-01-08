import telebot
from telebot import types
import netlas, requests, os, sqlite3, subprocess, json, glob, time, re, socket
from fpdf import FPDF
from datetime import datetime
from urllib.parse import quote

# ==========================================
# CONFIGURACIÓN DE IDENTIDAD
# ==========================================
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
INTELX_API_KEY = "dfb32516-4738-4b06-9e2c-4a6cee4cff00"

bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=True, num_threads=50)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# ==========================================
# MANEJADORES DE COMANDOS (v80.0)
# ==========================================

@bot.message_handler(commands=['start', 'help'])
def help_menu(message):
    if message.chat.id != TELEGRAM_CHAT_ID: return
    text = (
        "🚀 **ZENITH TITAN v80.0 - OMNI-INTELLIGENCE**\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "✨ **INTELIGENCIA EXTERNA (IntelX/Netlas)**\n"
        "🔓 `/logins` - Lista correos y subdominios (Phonebook)\n"
        "💀 `/dark_search` - Extrae claves de archivos filtrados\n"
        "🌐 `/scan` - Mapeo de infraestructura e IPs\n\n"
        "⚔️ **EXPLOTACIÓN Y AUDITORÍA**\n"
        "☢️ `/exploit` - Buscador de vulnerabilidades CVE\n"
        "🎯 `/find_bugs` - Escaneo Nmap + Reporte Vulnerabilidades\n\n"
        "📂 **GESTIÓN DE DATOS LOCALES**\n"
        "🔎 `/scan_url` - Buscar en tus archivos .txt subidos\n"
        "📩 `/upload_combo` - Subir base de datos de texto\n\n"
        "📊 `/status` - Estado de las APIs y archivos\n"
        "━━━━━━━━━━━━━━━━━━━━"
    )
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add('/logins', '/dark_search', '/scan', '/exploit', '/find_bugs', '/scan_url', '/upload_combo', '/status')
    bot.send_message(message.chat.id, text, parse_mode="Markdown", reply_markup=markup)

# --- 1. LOGINS (PHONEBOOK) ---
@bot.message_handler(commands=['logins'])
def ask_logins(message):
    msg = bot.send_message(message.chat.id, "📧 Ingrese dominio para listar correos e identidades:")
    bot.register_next_step_handler(msg, exec_phonebook)

def exec_phonebook(message):
    target = message.text.strip().lower()
    try:
        url = "https://public.intelx.io/phonebook/search"
        headers = {"x-key": INTELX_API_KEY}
        payload = {"term": target, "maxresults": 50, "media": 0, "target": 3}
        search_id = requests.post(url, headers=headers, json=payload).json().get('id')
        if search_id:
            time.sleep(2)
            results = requests.get(f"{url}/result?id={search_id}", headers=headers).json()
            leaks = [item['selectorValue'] for item in results.get('list', [])]
            out = f"📧 **IDENTIDADES HALLADAS:**\n\n" + "\n".join([f"• `{l}`" for l in leaks[:25]])
            bot.send_message(message.chat.id, out if leaks else "❌ Sin resultados.", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "⚠️ Error en IntelX.")

# --- 2. DARK SEARCH (CONTENIDO / CLAVES) ---
@bot.message_handler(commands=['dark_search'])
def ask_dark(message):
    msg = bot.send_message(message.chat.id, "🔑 Ingrese dominio o correo para extraer contraseñas:")
    bot.register_next_step_handler(msg, exec_dark_content)

def exec_dark_content(message):
    target = message.text.strip().lower()
    bot.send_message(message.chat.id, "☢️ Escaneando archivos filtrados...")
    try:
        url_search = "https://public.intelx.io/main/search"
        headers = {"x-key": INTELX_API_KEY}
        payload = {"term": f"{target} password", "maxresults": 5}
        search_id = requests.post(url_search, headers=headers, json=payload).json().get('id')
        if search_id:
            time.sleep(4)
            results = requests.get(f"{url_search}/result?id={search_id}", headers=headers).json()
            records = results.get('records', [])
            for rec in records[:3]:
                prev_url = f"https://public.intelx.io/file/preview?id={rec['storageid']}&sid={rec['systemid']}"
                preview = requests.get(prev_url, headers=headers).text[:400]
                bot.send_message(message.chat.id, f"📄 **Origen:** `{rec['name']}`\n🔑 **Data:**\n`{preview}`", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "⚠️ Error en Dark Search.")

# --- 3. SCAN (NETLAS) ---
@bot.message_handler(commands=['scan'])
def ask_scan(message):
    msg = bot.send_message(message.chat.id, "🌐 Ingrese dominio base:")
    bot.register_next_step_handler(msg, exec_scan_infra)

def exec_scan_infra(message):
    target = message.text.strip().lower()
    try:
        res = n_api.query(query=f"domain:*.{target}", datatype="domain")
        items = res.get('items', [])[:15]
        out = f"🛰 **INFRAESTRUCTURA:**\n\n"
        for i in items:
            d = i['data']['domain']
            try: ip = socket.gethostbyname(d); out += f"• `{d}` ➔ `{ip}`\n"
            except: out += f"• `{d}` ➔ `[No IP]`\n"
        bot.send_message(message.chat.id, out, parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Error Netlas.")

# --- 4. EXPLOIT (CVE) ---
@bot.message_handler(commands=['exploit'])
def ask_exploit(message):
    msg = bot.send_message(message.chat.id, "💀 Ingrese tecnología (ej: Apache, WordPress):")
    bot.register_next_step_handler(msg, exec_exploit_search)

def exec_exploit_search(message):
    tech = message.text.strip()
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(tech)}").json()
        v = r.get('vulnerabilities', [])[:5]
        out = f"☢️ **CVEs ENCONTRADOS:**\n\n"
        for i in v:
            cve_id = i['cve']['id']
            out += f"• {cve_id} ➔ [Exploit-DB](https://www.exploit-db.com/search?cve={cve_id[4:]})\n"
        bot.send_message(message.chat.id, out, parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ No hay resultados.")

# --- 5. SCAN_URL (LOCAL) ---
@bot.message_handler(commands=['scan_url'])
def ask_local(message):
    msg = bot.send_message(message.chat.id, "📂 Ingrese término de búsqueda local:")
    bot.register_next_step_handler(msg, exec_local_scan)

def exec_local_scan(message):
    query = message.text.strip().lower()
    matches = []
    for f in glob.glob("combos/*.txt"):
        with open(f, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                if query in line.lower(): matches.append(line.strip())
                if len(matches) >= 20: break
    bot.send_message(message.chat.id, "🔑 **RESULTADOS LOCALES:**\n\n" + "\n".join([f"`{m}`" for m in matches]) if matches else "❌ Sin datos.")

# --- 6. UPLOAD Y STATUS ---
@bot.message_handler(commands=['upload_combo'])
def upload_req(message):
    bot.send_message(message.chat.id, "📩 Envíame un archivo .txt para indexarlo.")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    if message.document.file_name.endswith('.txt'):
        f_info = bot.get_file(message.document.file_id)
        d_file = bot.download_file(f_info.file_path)
        if not os.path.exists("combos"): os.makedirs("combos")
        with open(f"combos/{message.document.file_name}", "wb") as f: f.write(d_file)
        bot.reply_to(message, "✅ Base de datos actualizada.")

@bot.message_handler(commands=['status'])
def status(message):
    num = len(glob.glob("combos/*.txt")) if os.path.exists("combos") else 0
    bot.send_message(message.chat.id, f"📊 **ESTADO:** ONLINE\n• IntelX: Activo\n• Netlas: Activo\n• Combos Locales: {num} archivos")

# --- 7. FIND_BUGS (NMAP) ---
@bot.message_handler(commands=['find_bugs'])
def ask_bugs(message):
    msg = bot.send_message(message.chat.id, "🎯 Ingrese IP o Dominio para auditar:")
    bot.register_next_step_handler(msg, exec_nmap)

def exec_nmap(message):
    target = message.text.strip()
    bot.send_message(message.chat.id, "🚀 Escaneando... espera el resultado.")
    try:
        res = subprocess.check_output(["nmap", "-F", "-Pn", "--script=vuln", target], timeout=300, text=True)
        bot.send_message(message.chat.id, f"✅ **RESULTADO:**\n`{res[:3000]}`", parse_mode="Markdown")
    except: bot.send_message(message.chat.id, "❌ Error en el escaneo.")

if __name__ == "__main__":
    print("🚀 ZENITH TITAN v80.0 OPERATIVO")
    bot.infinity_polling(skip_pending=True)
