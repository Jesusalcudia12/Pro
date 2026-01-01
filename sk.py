import telebot
from telebot import types
import netlas
import os
import sqlite3
from datetime import datetime, timedelta

# === CONFIGURACIÓN ===
NETLAS_API_KEY = "MheJyCwplJnLO8CU1ZOC7A7OkJFTYvnk"
TELEGRAM_TOKEN = "8583960709:AAGMxsIwVzlVUu-YvSn6Rfxn3-2Vfe-T3WU"
TELEGRAM_CHAT_ID = 6280594821 
MI_BILLETERA_USDT = "TWzf9VJmr2mhq5H8Xa3bLhbb8dwmWdG9B7I"

bot = telebot.TeleBot(TELEGRAM_TOKEN)

# --- BASE DE DATOS DE SEGUIMIENTO (Persistence) ---
def init_db():
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS objetivos 
                      (id INTEGER PRIMARY KEY, target TEXT, fecha_envio TEXT, pagado INTEGER)''')
    conn.commit()
    conn.close()

# --- LÓGICA DE SEGUIMIENTO ---
def registrar_objetivo(target):
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO objetivos (target, fecha_envio, pagado) VALUES (?, ?, 0)", (target, fecha))
    conn.commit()
    conn.close()

# --- COMANDO DE PÁNICO (VERIFICACIÓN) ---
@bot.message_handler(commands=['check_pendientes'])
def check_pendientes(message):
    conn = sqlite3.connect('zenith_business.db')
    cursor = conn.cursor()
    # Buscamos objetivos de hace más de 48 horas no pagados
    limite = (datetime.now() - timedelta(hours=48)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("SELECT target FROM objetivos WHERE fecha_envio < ? AND pagado = 0", (limite,))
    pendientes = cursor.fetchall()
    
    if pendientes:
        msg = "🚨 *ALERTA DE PÁNICO: OBJETIVOS SIN PAGO (48H+)*\n\n"
        for p in pendientes:
            msg += f"💀 `{p[0]}` - Acción sugerida: /exploit_deep\n"
        bot.send_message(TELEGRAM_CHAT_ID, msg, parse_mode="Markdown")
    else:
        bot.send_message(TELEGRAM_CHAT_ID, "✅ No hay cobros atrasados de alto riesgo.")
    conn.close()

# --- ACCIÓN AGRESIVA (RECON PROFUNDO) ---
@bot.message_handler(commands=['exploit_deep'])
def exploit_deep(message):
    bot.send_message(TELEGRAM_CHAT_ID, "🧨 *Iniciando Protocolo de Persistencia...*\nBuscando vectores de entrada críticos para forzar la negociación.", parse_mode="Markdown")
    # Aquí puedes llamar a los módulos de Dorks o Exploits de las versiones anteriores

@bot.callback_query_handler(func=lambda call: True)
def handle_query(call):
    if call.data == 'netlas_scan':
        msg = bot.send_message(call.message.chat.id, "🎯 Dominio/IP para reporte y seguimiento:")
        bot.register_next_step_handler(msg, ejecutar_negocio)

def ejecutar_negocio(message):
    target = message.text
    registrar_objetivo(target) # Guardamos en la lista negra/cobros
    bot.send_message(TELEGRAM_CHAT_ID, f"📝 Reporte generado y objetivo `{target}` añadido a seguimiento de 48h.", parse_mode="Markdown")
    # (Aquí iría la generación del reporte TXT anterior)

if __name__ == "__main__":
    init_db()
    os.system("clear")
    print("💀 ZENITH THE ENFORCER v31.0 ONLINE")
    bot.infinity_polling()
