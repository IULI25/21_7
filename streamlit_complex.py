import sqlite3
import hashlib
import os
import hmac

conn = sqlite3.connect('users_data.db')
cursor = conn.cursor()
 
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
''')
 
cursor.execute('''
CREATE TABLE IF NOT EXISTS raport (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    valoare INTEGER,
    categorie TEXT
    data TEXT
)
''')
conn.commit()

cursor.execute("PRAGMA table_info(raport)")
coloane_existente = [col[1] for col in cursor.fetchall()]
if 'data' not in coloane_existente:
    cursor.execute("ALTER TABLE raport ADD COLUMN data TEXT")
    conn.commit()

def hash_password(password, salt=None):
    """ÃŽntoarce 'salt$hash'. Salt nou, aleator, dacÄƒ nu e dat unul."""
    if salt is None:
        salt = os.urandom(16)
    hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}${hash.hex()}"

def verify_password(password, stored):
    """ComparÄƒ parola introdusÄƒ cu valoarea 'salt$hash' din baza de date."""
    try:
        salt_hex, _ = stored.split('$')
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    # compare_digest evitÄƒ scurgerea de informaÈ›ie prin timpul de comparare
    return hmac.compare_digest(hash_password(password, salt), stored)

def register_user(username, password):
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
    conn.commit()

def login_user(username, password):
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    rezultat = cursor.fetchone()
    if rezultat and verify_password(password, rezultat[2]):
        return rezultat
    return None

import streamlit as st
import pandas as pd
from datetime import date

st.title("ðŸ” Sistem securizat Streamlit + SQLite")

if 'user' in st.session_state:
    user = st.session_state['user']
    st.sidebar.write(f"Conectat ca **{user}**")
    if st.sidebar.button("ðŸšª IeÈ™i"):
        del st.session_state['user']
        st.rerun()

    # Dashboard
    st.subheader(":bar_chart: Dashboard")
    val = st.number_input("Introdu valoare")
    cat = st.selectbox("Categorie", ["Alimente", "Transport", "DistracÈ›ie"])
    data_cheltuiala = st.date_input("Data", value=date.today())
    if st.button(":inbox_tray: SalveazÄƒ"):
       cursor.execute(
    "INSERT INTO raport (user, valoare, categorie, data) VALUES (?, ?, ?, ?)",
    (user, val, cat, data_cheltuiala.isoformat())
)
        conn.commit()
        st.success("Date salvate!")

    # Vizualizare
    st.subheader(":mag: Istoric cheltuieli")
    df = pd.read_sql_query("SELECT * FROM raport WHERE user=?", conn, params=(user,))

    df_filtrat = df.copy()
    if not df.empty:
        df_filtrat['data'] = pd.to_datetime(df_filtrat['data'], errors='coerce')

    st.markdown("**Filtreaza dupa:**")
        col_an, col_luna = st.columns(2)

        ani_disponibili = sorted(df_filtrat['data'].dt.year.dropna().unique().astype(int), reverse=True)
        with col_an:
            an_selectat = st.selectbox("An", ["Toate anii"] + [str(a) for a in ani_disponibili])

        luni_ro = ["Toate lunile", "Ianuarie", "Februarie", "Martie", "Aprilie", "Mai", "Iunie",
                   "Iulie", "August", "Septembrie", "Octombrie", "Noiembrie", "Decembrie"]
        with col_luna:
            luna_selectata = st.selectbox("LunÄƒ", luni_ro)

              if an_selectat != "Toate anii":
            df_filtrat = df_filtrat[df_filtrat['data'].dt.year == int(an_selectat)]
        if luna_selectata != "Toate lunile":
            numar_luna = luni_ro.index(luna_selectata)  # 1-12
            df_filtrat = df_filtrat[df_filtrat['data'].dt.month == numar_luna]

    st.dataframe(df_filtrat)
 

    # Grafic
     if not df_filtrat.empty:
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots()
        df_filtrat.groupby('categorie')['valoare'].sum().plot(kind='bar', ax=ax)
        st.pyplot(fig)

    # Export
    st.download_button("ðŸ—ƒ ExportÄƒ CSV", df_filtrat.to_csv(index=False), file_name="raport.csv")

    st.stop()

menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Meniu", menu)

if choice == "Register":
    st.subheader("ðŸ‘¤ Creare cont")
    user = st.text_input("Username")
    pw = st.text_input("ParolÄƒ", type="password")
    if st.button("âœ… CreeazÄƒ cont"):
        register_user(user, pw)
        st.success("Cont creat cu succes!")
 
elif choice == "Login":
    st.subheader(":lock: Autentificare")
    user = st.text_input("Username")
    pw = st.text_input("ParolÄƒ", type="password")
    if st.button("ðŸ”“ IntrÄƒ"):
        rezultat = login_user(user, pw)
        if rezultat:
            st.session_state['user'] = user
            st.rerun()
        else:
            st.error("Utilizator sau parolÄƒ greÈ™itÄƒ")
