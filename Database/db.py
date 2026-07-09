import sqlite3
from datetime import datetime

def conectar():
    conexao = sqlite3.connect("aspm.db", check_same_thread=False)
    return conexao

def criar_tabela():
    conexao = conectar()
    cursor = conexao.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            nome TEXT,
            criado_em TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            nome TEXT,
            tipo TEXT,
            url TEXT,
            ambiente TEXT,
            criticidade TEXT,
            score INTEGER,
            analise TEXT,
            ultima_analise TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            ativo_nome TEXT,
            tipo TEXT,
            mensagem TEXT,
            data TEXT,
            resolvido INTEGER DEFAULT 0,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            score_medio REAL,
            data TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ativo_id INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL,
            nome TEXT,
            score INTEGER,
            data TEXT,
            FOREIGN KEY (ativo_id) REFERENCES ativos (id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS configuracoes (
            chave TEXT PRIMARY KEY,
            valor TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            usuario_nome TEXT,
            nivel TEXT,
            acao TEXT NOT NULL,
            aplicacao TEXT,
            ambiente TEXT,
            detalhe TEXT,
            origem TEXT,
            data TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    for sql in [
        "ALTER TABLE ativos ADD COLUMN usuario_id INTEGER",
        "ALTER TABLE alertas ADD COLUMN usuario_id INTEGER",
        "ALTER TABLE historico ADD COLUMN usuario_id INTEGER",
        "ALTER TABLE ativos ADD COLUMN ultima_analise TEXT",
        "ALTER TABLE logs ADD COLUMN nivel TEXT",
        "ALTER TABLE logs ADD COLUMN aplicacao TEXT",
        "ALTER TABLE logs ADD COLUMN ambiente TEXT",
        "ALTER TABLE logs ADD COLUMN origem TEXT",
    ]:
        try:
            cursor.execute(sql)
        except Exception:
            pass

    cursor.execute("""
        INSERT OR IGNORE INTO configuracoes (chave, valor)
        VALUES ('intervalo_rescan_minutos', '60')
    """)

    conexao.commit()


# =====================================
# CONFIGURAÇÕES
# =====================================

def get_intervalo_rescan() -> int:
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT valor FROM configuracoes WHERE chave = 'intervalo_rescan_minutos'")
    resultado = cursor.fetchone()
    return int(resultado[0]) if resultado else 60

def set_intervalo_rescan(minutos: int):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO configuracoes (chave, valor) VALUES ('intervalo_rescan_minutos', ?)",
        (str(minutos),)
    )
    conexao.commit()


# =====================================
# LOGS (AUDIT TRAIL)
# =====================================

def registrar_log(
    usuario_id: int,
    usuario_nome: str,
    acao: str,
    detalhe: str = "",
    nivel: str = "INFORMATIVO",
    aplicacao: str = "*",
    ambiente: str = "Todos",
    origem: str = "Plataforma"
):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT INTO logs (usuario_id, usuario_nome, nivel, acao, aplicacao, ambiente, detalhe, origem, data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        usuario_id, usuario_nome, nivel, acao,
        aplicacao, ambiente, detalhe, origem,
        datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    ))
    conexao.commit()

def listar_logs(usuario_id: int, limite: int = 100):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, data, nivel, acao, aplicacao, ambiente, detalhe, origem, usuario_nome
        FROM logs
        WHERE usuario_id = ?
        ORDER BY id DESC
        LIMIT ?
    """, (usuario_id, limite))
    return cursor.fetchall()

def limpar_logs(usuario_id: int):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("DELETE FROM logs WHERE usuario_id = ?", (usuario_id,))
    conexao.commit()


# =====================================
# USUÁRIOS
# =====================================

def criar_usuario(username, email, senha_hash, nome):
    conexao = conectar()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            INSERT INTO usuarios (username, email, senha_hash, nome, criado_em)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, senha_hash, nome, datetime.now().strftime("%d/%m/%Y %H:%M")))
        conexao.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None

def buscar_usuario_por_username(username):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT id, username, email, senha_hash, nome FROM usuarios WHERE username = ?",
        (username,)
    )
    return cursor.fetchone()

def buscar_usuario_por_id(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT id, username, email, senha_hash, nome FROM usuarios WHERE id = ?",
        (usuario_id,)
    )
    return cursor.fetchone()


# =====================================
# ATIVOS
# =====================================

def salvar_ativo(usuario_id, nome, tipo, url, ambiente, criticidade, score, analise):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT INTO ativos (
            usuario_id, nome, tipo, url, ambiente, criticidade, score, analise, ultima_analise
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (usuario_id, nome, tipo, url, ambiente, criticidade, score, analise,
          datetime.now().strftime("%d/%m/%Y %H:%M")))
    conexao.commit()

def atualizar_ativo(usuario_id, nome, url, criticidade, score, analise):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        UPDATE ativos
        SET criticidade = ?, score = ?, analise = ?, ultima_analise = ?
        WHERE usuario_id = ? AND nome = ? AND url = ?
    """, (criticidade, score, analise, datetime.now().strftime("%d/%m/%Y %H:%M"),
          usuario_id, nome, url))
    conexao.commit()

def listar_ativos_db(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM ativos WHERE usuario_id = ?", (usuario_id,))
    return cursor.fetchall()

def deletar_ativo(usuario_id, ativo_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT nome FROM ativos WHERE id = ? AND usuario_id = ?", (ativo_id, usuario_id))
    resultado = cursor.fetchone()
    cursor.execute("DELETE FROM ativos WHERE id = ? AND usuario_id = ?", (ativo_id, usuario_id))
    if resultado:
        cursor.execute("DELETE FROM alertas WHERE ativo_nome = ? AND usuario_id = ?", (resultado[0], usuario_id))
    conexao.commit()


# =====================================
# HISTÓRICO (MÉDIA GERAL - USADO NO GRÁFICO DE EVOLUÇÃO DE RISCO)
# =====================================

def registrar_historico(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT score FROM ativos WHERE usuario_id = ? AND criticidade != 'Erro'", (usuario_id,))
    scores = [r[0] for r in cursor.fetchall()]
    if not scores:
        return
    score_medio = sum(scores) / len(scores)
    cursor.execute(
        "INSERT INTO historico (usuario_id, score_medio, data) VALUES (?, ?, ?)",
        (usuario_id, score_medio, datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    )
    conexao.commit()

def listar_historico(usuario_id, minutos=60):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT score_medio, data FROM historico
        WHERE usuario_id = ?
        ORDER BY id DESC LIMIT 50
    """, (usuario_id,))
    resultados = cursor.fetchall()
    if not resultados:
        return []
    agora = datetime.now()
    filtrados = []
    for score_medio, data_str in resultados:
        data_ponto = datetime.strptime(data_str, "%d/%m/%Y %H:%M:%S")
        if (agora - data_ponto).total_seconds() <= minutos * 60:
            filtrados.append((score_medio, data_str))
    return list(reversed(filtrados))


# =====================================
# HISTÓRICO POR ATIVO (USADO NA DETECÇÃO DE ANOMALIAS COM ML)
# =====================================

def registrar_historico_ativo(usuario_id, ativo_id, nome, score):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT INTO historico_ativos (ativo_id, usuario_id, nome, score, data)
        VALUES (?, ?, ?, ?, ?)
    """, (ativo_id, usuario_id, nome, score, datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conexao.commit()

def listar_historico_ativo(usuario_id, ativo_id, limite=50):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT score, data FROM historico_ativos
        WHERE usuario_id = ? AND ativo_id = ?
        ORDER BY id ASC
        LIMIT ?
    """, (usuario_id, ativo_id, limite))
    return cursor.fetchall()


# =====================================
# ALERTAS
# =====================================

def salvar_alerta(usuario_id, ativo_nome, tipo, mensagem):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id FROM alertas
        WHERE usuario_id = ? AND ativo_nome = ? AND tipo = ? AND mensagem = ? AND resolvido = 0
        LIMIT 1
    """, (usuario_id, ativo_nome, tipo, mensagem))
    if cursor.fetchone():
        return
    cursor.execute(
        "INSERT INTO alertas (usuario_id, ativo_nome, tipo, mensagem, data) VALUES (?, ?, ?, ?, ?)",
        (usuario_id, ativo_nome, tipo, mensagem, datetime.now().strftime("%d/%m/%Y %H:%M"))
    )
    conexao.commit()

def listar_alertas_ativos(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT * FROM alertas
        WHERE usuario_id = ? AND resolvido = 0
        ORDER BY id DESC LIMIT 10
    """, (usuario_id,))
    return cursor.fetchall()

def resolver_alerta(usuario_id, alerta_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("UPDATE alertas SET resolvido = 1 WHERE id = ? AND usuario_id = ?", (alerta_id, usuario_id))
    conexao.commit()