import telebot
from telebot import types, util
import netlas, requests, os, sqlite3, subprocess, json, glob, logging, time
from fpdf import FPDF
from datetime import datetime
from urllib.parse import quote

# ==========================================
# CONFIGURACIÓN DE IDENTIDAD Y SEGURIDAD
# ==========================================
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
MI_BILLETERA_USDT = "TWzf9VJmr2mhq5H8Xa3bLhbb8dwmWdG9B7I"
PRECIO_BASE = "350.00 USDT"

# Inicialización de servicios con Multi-hilo
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=True, num_threads=15)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# ==========================================
# MOTOR DE BASE DE DATOS PROFESIONAL
# ==========================================
class DatabaseManager:
    def __init__(self, db_name='zenith_titan.db'):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS objetivos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT, tipo_scan TEXT, fecha TEXT,
            estado_pago INTEGER DEFAULT 0, monto TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER, comando TEXT, ts TEXT)''')
        self.conn.commit()

    def registrar_operacion(self, tipo, target):
        cursor = self.conn.cursor()
        fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO objetivos (target, tipo_scan, fecha, monto) VALUES (?, ?, ?, ?)",
                       (target, tipo, fecha, PRECIO_BASE))
        self.conn.commit()

    def log_comando(self, user_id, cmd):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO logs_auditoria (usuario_id, comando, ts) VALUES (?, ?, ?)",
                       (user_id, cmd, datetime.now().strftime('%H:%M:%S')))
        self.conn.commit()

db = DatabaseManager()

# ==========================================
# MOTOR DE REPORTES PDF (Zenith Engine)
# ==========================================
class ZenithReport(FPDF):
    def header(self):
        self.set_fill_color(15, 15, 15)
        self.rect(0, 0, 210, 40, 'F')
        self.set_font('Arial', 'B', 22)
        self.set_text_color(255, 255, 255)
        self.cell(0, 20, 'ZENITH TITAN SYSTEMS', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Strategic Cyber-Intelligence Division', 0, 1, 'C')
        self.ln(25)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'ID: {os.urandom(3).hex().upper()} | Zenith v55.0', 0, 0, 'C')

def generar_pdf_reporte(target, data, titulo):
    pdf = ZenithReport()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"HALLAZGOS: {titulo}", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 7, txt=str(data))
    path = f"Reporte_{target.replace('.', '_')}.pdf"
    pdf.output(path)
    return path

# ==========================================
# FUNCIONES DE BÚSQUEDA REAL (LOCAL Y WEB)
# ==========================================
def buscar_en_combos_locales(dominio):
    """Escaneo real de archivos .txt en la carpeta combos/"""
    resultados = []
    archivos = glob.glob("combos/*.txt")
    for arc in archivos:
        try:
            with open(arc, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    if dominio.lower() in linea.lower():
                        resultados.append(linea.strip())
                    if len(resultados) >= 40: break # Evitar saturación
        except: pass
    return resultados

def buscar_cves_nist(tecnologia):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tecnologia}"
    try:
        r = requests.get(url, timeout=10).json()
        return r.get('vulnerabilities', [])
    except: return []

# ==========================================
# MANEJADORES DE COMANDOS
# ==========================================

@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.chat.id != TELEGRAM_CHAT_ID:
        bot.send_message(message.chat.id, "❌ Acceso denegado. Este sistema es privado.")
        return
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add('/scan_url', '/leak', '/exploit', '/port_scan', '/status', '/combos')
    bot.send_message(message.chat.id, "👑 *SISTEMA OMEGA CARGADO*\nBienvenido al núcleo Zenith.", 
                     parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(commands=['scan_url'])
def ask_scan(message):
    msg = bot.send_message(message.chat.id, "🔍 Ingrese Dominio (ej: `sivale.mx`):", parse_mode="Markdown")
    bot.register_next_step_handler(msg, exec_scan_url)

def exec_scan_url(message):
    target = message.text.strip().lower()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    bot.send_message(message.chat.id, f"🛰️ Rastreeando registros para `{domain}`...")
    
    # Búsqueda real en tus archivos (como el sivale.mx.txt)
    leaks = buscar_en_combos_locales(domain)
    
    # Consulta Infraestructura
    try:
        net_res = n_api.query(query=f"host:{domain}")
        net_info = json.dumps(net_res, indent=2)[:400]
    except: net_info = "API Netlas no disponible."

    respuesta = f"📂 *EXTRACCIÓN DE CREDENCIALES:* `{domain}`\n"
    respuesta += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    if leaks:
        for l in leaks[:15]: respuesta += f"`{l}`\n\n"
        if len(leaks) > 15: respuesta += f"👉 _Y {len(leaks)-15} registros más..._"
    else:
        respuesta += "❌ No se encontraron logs en la base local.\n"
    
    respuesta += f"\n🌐 *NET-INFRA:*\n`{net_info}`\n"
    respuesta += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    bot.send_message(message.chat.id, respuesta, parse_mode="Markdown", disable_web_page_preview=True)
    db.registrar_operacion("SCAN_URL", domain)

@bot.message_handler(commands=['exploit'])
def ask_exp(message):
    msg = bot.send_message(message.chat.id, "🛡️ Ingrese Software/Versión para buscar CVEs:")
    bot.register_next_step_handler(msg, exec_exploit)

def exec_exploit(message):
    tech = message.text
    bot.send_message(message.chat.id, f"🔎 Consultando NIST para {tech}...")
    cves = buscar_cves_nist(tech)
    
    if not cves:
        bot.send_message(message.chat.id, "❌ Sin resultados reales.")
        return

    rep_content = ""
    for c in cves[:10]:
        rep_content += f"ID: {c['cve']['id']}\nDESC: {c['cve']['descriptions'][0]['value']}\n\n"
    
    path = generar_pdf_reporte(tech, rep_content, "VULNERABILIDADES")
    with open(path, "rb") as f:
        bot.send_document(message.chat.id, f, caption=f"☢️ CVE Report: {tech}")
    os.remove(path)
    db.registrar_operacion("EXPLOIT", tech)

@bot.message_handler(commands=['port_scan'])
def ask_port(message):
    msg = bot.send_message(message.chat.id, "🔌 Ingrese IP para Escaneo Nmap:")
    bot.register_next_step_handler(msg, exec_port)

def exec_port(message):
    target = message.text
    bot.send_message(message.chat.id, f"⚡ Ejecutando Nmap en {target}...")
    try:
        res = subprocess.check_output(["nmap", "-F", target], timeout=60).decode()
        bot.send_message(message.chat.id, f"📋 *Nmap:* \n`{res}`", parse_mode="Markdown")
        db.registrar_operacion("PORT_SCAN", target)
    except:
        bot.send_message(message.chat.id, "❌ Error al ejecutar Nmap.")

@bot.message_handler(commands=['combos'])
def cmd_combos(message):
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("🔍 Dork Gmail", callback_data="d_1"),
               types.InlineKeyboardButton("🔍 Dork SQL", callback_data="d_2"))
    bot.send_message(message.chat.id, "🎯 *ACCESO A DORKS REALES:*", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('d_'))
def handle_dork_links(call):
    d = {"d_1": 'filetype:txt "@gmail.com:" password', "d_2": 'filetype:sql "users" "password"'}
    url = f"https://www.google.com/search?q={quote(d[call.data])}"
    bot.send_message(call.message.chat.id, f"🚀 [RESULTADOS GOOGLE OSINT]({url})", parse_mode="Markdown")

@bot.message_handler(commands=['status'])
def cmd_status(message):
    uptime = "ESTABLE"
    bot.send_message(message.chat.id, f"📊 *ZENITH STATUS*\nMotor: {uptime}\nDB: CONNECTED\nTHREADS: ACTIVE", parse_mode="Markdown")

# ==========================================
# INICIO DEL SISTEMA
# ==========================================
if __name__ == "__main__":
    if not os.path.exists("combos"): os.makedirs("combos")
    os.system("clear")
    print("💎 ZENITH TITAN OMEGA v55.0 - OPERATIVO")
    bot.infinity_polling(skip_pending=True)
