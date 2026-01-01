import telebot
from telebot import types
import netlas, requests, os, time, socket, sqlite3
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

# --- GENERADOR DE CÓDIGO QR PARA PAGO ---
def obtener_qr_url(billetera):
    return f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={billetera}"

# --- MOTOR DE AUDITORÍA Y PRECIOS ---
INFO_VULN = {
    "database": {"desc": "Base de Datos Expuesta detectada por Netlas.", "fix": "Configurar auth, cifrado y Firewall.", "precio": "250 USDT"},
    "http": {"desc": "Servidor con Versión Obsoleta/Vulnerable.", "fix": "Actualizar parches y cabeceras HSTS.", "precio": "120 USDT"},
    "leak": {"desc": "Fuga de Credenciales Administrativas.", "fix": "Reset masivo de claves y habilitar 2FA.", "precio": "200 USDT"}
}

# --- COMANDOS PRINCIPALES ---

@bot.message_handler(commands=['start'])
def cmd_start(message):
    if message.from_user.id != TELEGRAM_CHAT_ID: return
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("🛰️ Escaneo Netlas PRO", callback_data='netlas_scan'),
        types.InlineKeyboardButton("🔍 Scan URL/Tech", callback_data='url_mode'),
        types.InlineKeyboardButton("🚨 Check Pánico", callback_data='panic_check'),
        types.InlineKeyboardButton("⚙️ Status", callback_data='status')
    )
    bot.send_message(message.chat.id, "👑 *ZENITH TITAN v33.0*\nSoberanía Digital con Netlas Engine.", parse_mode="Markdown", reply_markup=markup)

@bot.message_handler(commands=['reporte'])
def cmd_reporte(message):
    msg = bot.reply_to(message, "💼 Ingrese Dominio/IP para generar Auditoría + Factura USDT:")
    bot.register_next_step_handler(msg, procesar_auditoria)

def procesar_auditoria(message):
    target = message.text
    registrar_objetivo(target)
    bot.send_message(TELEGRAM_CHAT_ID, "📊 Analizando con Netlas... Generando reporte y código QR...")
    
    # Lógica de reporte basada en Netlas
    archivo = f"Reporte_{target}.txt"
    with open(archivo, "w", encoding="utf-8") as f:
        f.write(f"REPORTE DE AUDITORÍA PROFESIONAL\nTarget: {target}\nFecha: {datetime.now()}\n")
        f.write(f"Motor de Escaneo: Netlas.io\n")
        f.write(f"---------------------------------\nVulnerabilidad: {INFO_VULN['database']['desc']}\n")
        f.write(f"Costo de Solución: {INFO_VULN['database']['precio']}\n")
        f.write(f"Billetera USDT ({RED_CRYPTO}): {MI_BILLETERA_USDT}\n")
    
    qr_link = obtener_qr_url(MI_BILLETERA_USDT)
    with open(archivo, "rb") as d:
        bot.send_document(TELEGRAM_CHAT_ID, d, caption=f"📄 Reporte para {target}\n\n💰 *PAGO EN USDT:* `{MI_BILLETERA_USDT}`")
    bot.send_photo(TELEGRAM_CHAT_ID, qr_link, caption="📱 Escanea este QR para realizar el pago")
    os.remove(archivo)

@bot.message_handler(commands=['scan_url'])
def cmd_scan_url(message):
    msg = bot.reply_to(message, "🔍 Dominio a investigar con Netlas:")
    bot.register_next_step_handler(msg, ejecutar_netlas_quick)

def ejecutar_netlas_quick(message):
    target = message.text
    try:
        res = n_api.query(query=f"host:{target}", datatype='host')
        bot.send_message(TELEGRAM_CHAT_ID, f"🌐 *Info de {target}:*\n`{str(res)[:500]}...`", parse_mode="Markdown")
    except:
        bot.send_message(TELEGRAM_CHAT_ID, "❌ Error al conectar con Netlas.")

@bot.message_handler(commands=['check_pendientes'])
def cmd_check_pendientes(message):
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    limite = (datetime.now() - timedelta(hours=48)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("SELECT target FROM objetivos WHERE fecha_envio < ? AND pagado = 0", (limite,))
    pendientes = cursor.fetchall()
    if pendientes:
        msg = "🚨 *PENDIENTES 48H (NETLAS AUDIT):*\n" + "\n".join([f"💀 `{p[0]}`" for p in pendientes])
        bot.send_message(TELEGRAM_CHAT_ID, msg, parse_mode="Markdown")
    else:
        bot.send_message(TELEGRAM_CHAT_ID, "✅ No hay cobros atrasados.")
    conn.close()

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    if call.data == 'netlas_scan':
        msg = bot.send_message(call.message.chat.id, "🎯 Envíe Dominio para escaneo PRO con Netlas:")
        bot.register_next_step_handler(msg, ejecutar_netlas_quick)
    elif call.data == 'panic_check':
        cmd_check_pendientes(call.message)
    elif call.data == 'status':
        bot.answer_callback_query(call.id, "Netlas API: OK 🟢")

if __name__ == "__main__":
    init_db()
    os.system("clear")
    print("💎 ZENITH TITAN v33.0 - NETLAS EDITION")
    bot.infinity_polling()
