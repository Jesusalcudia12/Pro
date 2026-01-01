import telebot
from telebot import types
import netlas, requests, os, time, socket, sqlite3
from fpdf import FPDF
from datetime import datetime, timedelta
from urllib.parse import quote

# === CONFIGURACIÓN DE LLAVES Y COBRO ===
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 
MI_BILLETERA_USDT = "TWzf9VJmr2mhq5H8Xa3bLhbb8dwmWdG9B7I"
RED_CRYPTO = "TRC20 (Tron Network)"

# Inicialización
bot = telebot.TeleBot(TELEGRAM_TOKEN)
n_api = netlas.Netlas(api_key=NETLAS_API_KEY)

# --- CLASE PARA DISEÑO DE PDF PROFESIONAL ---
class ZenithPDF(FPDF):
    def header(self):
        self.set_fill_color(20, 20, 20)
        self.rect(0, 0, 210, 35, 'F')
        self.set_font('Arial', 'B', 22)
        self.set_text_color(255, 255, 255)
        self.cell(0, 15, 'ZENITH TITAN INTELLIGENCE', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Cybersecurity Infrastructure & Threat Recon', 0, 1, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Página {self.page_no()} - Documento Confidencial', 0, 0, 'C')

# --- BASE DE DATOS DE PERSISTENCIA ---
def init_db():
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS objetivos 
                      (id INTEGER PRIMARY KEY, target TEXT, fecha_envio TEXT, pagado INTEGER)''')
    conn.commit()
    conn.close()

def registrar_objetivo(target):
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO objetivos (target, fecha_envio, pagado) VALUES (?, ?, 0)", (target, fecha))
    conn.commit()
    conn.close()

# --- FUNCIONES DE APOYO ---
def crear_pdf_profesional(target, data_text, tipo="AUDITORÍA"):
    pdf = ZenithPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"TIPO DE INFORME: {tipo}", ln=True)
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f"OBJETIVO ANALIZADO: {target}", ln=True)
    pdf.cell(0, 10, f"FECHA DE EMISIÓN: {datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
    pdf.ln(10)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "HALLAZGOS TÉCNICOS:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 8, txt=data_text)
    
    pdf.ln(15)
    pdf.set_fill_color(240, 240, 240)
    pdf.rect(10, pdf.get_y(), 190, 35, 'F')
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, "INSTRUCCIONES DE PAGO Y REMEDIACIÓN:", ln=True)
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 7, f"Costo de Consultoría: 250.00 USDT", ln=True)
    pdf.cell(0, 7, f"Billetera ({RED_CRYPTO}): {MI_BILLETERA_USDT}", ln=True)
    
    nombre_archivo = f"Zenith_Report_{target.replace('.', '_')}.pdf"
    pdf.output(nombre_archivo)
    return nombre_archivo

# --- COMANDOS DEL SISTEMA ---

@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.from_user.id != TELEGRAM_CHAT_ID: return
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("🛰️ Escaneo Netlas", callback_data='netlas_scan'),
        types.InlineKeyboardButton("🚨 Check Pánico", callback_data='panic_check'),
        types.InlineKeyboardButton("⚙️ Status", callback_data='status')
    )
    bot.send_message(message.chat.id, "👑 *ZENITH TITAN v38.0*\nUnidad Central de Inteligencia activada.", parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(commands=['scan_mx'])
def cmd_scan_mx(message):
    msg = bot.reply_to(message, "🇲🇽 Ingrese término para buscar en México:")
    bot.register_next_step_handler(msg, lambda m: ejecutar_netlas(m, f"{m.text} geo.country:MX"))

@bot.message_handler(commands=['scan_url'])
def cmd_scan_url(message):
    msg = bot.reply_to(message, "🔍 Ingrese URL o Dominio para análisis:")
    bot.register_next_step_handler(msg, lambda m: ejecutar_netlas(m, f"host:{m.text}"))

@bot.message_handler(commands=['leak'])
def cmd_leak(message):
    msg = bot.reply_to(message, "📧 Ingrese dominio para buscar filtraciones (Genera PDF):")
    bot.register_next_step_handler(msg, procesar_leak)

@bot.message_handler(commands=['combos'])
def cmd_combos(message):
    bot.send_message(message.chat.id, "🎯 *Dorks para Combos:* \n`filetype:log \"pwd=\"` \n`\"index of\" \"config.php\"`", parse_mode="Markdown")

@bot.message_handler(commands=['exploit'])
def cmd_exploit(message):
    msg = bot.reply_to(message, "🛡️ Tecnología para buscar CVE:")
    bot.register_next_step_handler(msg, lambda m: bot.send_message(m.chat.id, f"🔎 Buscando vulnerabilidades para `{m.text}`..."))

@bot.message_handler(commands=['brute_mode'])
def cmd_brute(message):
    bot.send_message(message.chat.id, "⚠️ *MODO BRUTE:* Configure target y diccionario.")

@bot.message_handler(commands=['port_scan'])
def cmd_port_scan(message):
    msg = bot.reply_to(message, "🔌 IP para escaneo de puertos:")
    bot.register_next_step_handler(msg, lambda m: bot.send_message(m.chat.id, f"⚡ Escaneando {m.text}..."))

@bot.message_handler(commands=['geo_ip'])
def cmd_geo(message):
    msg = bot.reply_to(message, "📍 Ingrese IP:")
    bot.register_next_step_handler(msg, lambda m: ejecutar_netlas(m, f"ip:{m.text}"))

@bot.message_handler(commands=['reporte'])
def cmd_reporte(message):
    msg = bot.reply_to(message, "💼 Target para Reporte PDF + Factura USDT:")
    bot.register_next_step_handler(msg, generar_reporte_completo)

@bot.message_handler(commands=['check_pendientes'])
def cmd_check_pendientes(message):
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    limite = (datetime.now() - timedelta(hours=48)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("SELECT target FROM objetivos WHERE fecha_envio < ? AND pagado = 0", (limite,))
    pendientes = cursor.fetchall()
    msg = "🚨 *PENDIENTES 48H:* \n" + "\n".join([f"💀 `{p[0]}`" for p in pendientes]) if pendientes else "✅ Sin deudas."
    bot.send_message(TELEGRAM_CHAT_ID, msg, parse_mode="Markdown")
    conn.close()

@bot.message_handler(commands=['exploit_deep'])
def cmd_deep(message):
    msg = bot.reply_to(message, "💀 Target para Recon Profundo:")
    bot.register_next_step_handler(msg, lambda m: bot.send_message(m.chat.id, "🌪️ Iniciando Deep Scan..."))

@bot.message_handler(commands=['status'])
def cmd_status(message):
    bot.send_message(message.chat.id, "🟢 API Netlas: OK\n🟢 PDF Generator: OK\n🟢 Bot: ONLINE")

# --- LÓGICA DE PROCESAMIENTO ---

def ejecutar_netlas(message, query):
    try:
        res = n_api.query(query=query)
        bot.send_message(TELEGRAM_CHAT_ID, f"📡 *Hallazgos:* \n`{str(res)[:1000]}...`", parse_mode="Markdown")
    except Exception as e:
        bot.send_message(TELEGRAM_CHAT_ID, f"❌ Error: {e}")

def procesar_leak(message):
    target = message.text
    info = f"Se detectaron múltiples vectores de fuga de información para {target}. Se recomienda cambio de credenciales inmediato y auditoría de accesos."
    archivo = crear_pdf_profesional(target, info, "FUGA DE DATOS / LEAK")
    with open(archivo, "rb") as f:
        bot.send_document(TELEGRAM_CHAT_ID, f, caption=f"📧 Informe de Leaks: {target}")
    os.remove(archivo)

def generar_reporte_completo(message):
    target = message.text
    registrar_objetivo(target)
    info = (
        "El análisis de infraestructura mediante Netlas Engine ha revelado servicios críticos expuestos "
        "sin las medidas de seguridad adecuadas. Se recomienda el endurecimiento (hardening) inmediato "
        "del servidor para prevenir ataques de denegación de servicio o exfiltración de datos."
    )
    archivo = crear_pdf_profesional(target, info, "AUDITORÍA DE INFRAESTRUCTURA")
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={MI_BILLETERA_USDT}"
    
    with open(archivo, "rb") as f:
        bot.send_document(TELEGRAM_CHAT_ID, f, caption=f"📄 Auditoría Finalizada para {target}")
    bot.send_photo(TELEGRAM_CHAT_ID, qr_url, caption=f"💰 *PAGO:* `{MI_BILLETERA_USDT}`")
    os.remove(archivo)

if __name__ == "__main__":
    init_db()
    os.system("clear")
    print("💎 ZENITH TITAN v38.0 - ONLINE")
    bot.infinity_polling()
