import sqlite3
import bcrypt
import os
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
        "ALTER TABLE usuarios ADD COLUMN role TEXT DEFAULT 'usuario'",
        "ALTER TABLE usuarios ADD COLUMN mfa_code TEXT",
        "ALTER TABLE usuarios ADD COLUMN mfa_expira TEXT",
        "ALTER TABLE usuarios ADD COLUMN mfa_tentativas INTEGER DEFAULT 0",
        # CSPM (AWS) - abordagem via AssumeRole: guardamos apenas o ARN da role
        # e a regiao. Nao ha credenciais de longa duracao armazenadas aqui.
        "ALTER TABLE ativos ADD COLUMN aws_role_arn TEXT",
        "ALTER TABLE ativos ADD COLUMN aws_region TEXT",
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
    criar_admin_padrao()


def criar_admin_padrao():
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_email    = os.environ.get("ADMIN_EMAIL")
    admin_senha    = os.environ.get("ADMIN_PASSWORD")

    if not admin_username or not admin_email or not admin_senha:
        return

    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT id FROM usuarios WHERE username = ?", (admin_username,))
    if cursor.fetchone():
        return

    senha_hash = bcrypt.hashpw(admin_senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    cursor.execute("""
        INSERT INTO usuarios (username, email, senha_hash, nome, criado_em, role)
        VALUES (?, ?, ?, ?, ?, 'admin')
    """, (admin_username, admin_email, senha_hash, "Administrador",
          datetime.now().strftime("%d/%m/%Y %H:%M")))
    conexao.commit()


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

def listar_logs_todos(limite: int = 200):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, data, nivel, acao, aplicacao, ambiente, detalhe, origem, usuario_nome
        FROM logs
        ORDER BY id DESC
        LIMIT ?
    """, (limite,))
    return cursor.fetchall()

def contar_usuarios() -> int:
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    return cursor.fetchone()[0]

def contar_admins() -> int:
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE role = 'admin'")
    return cursor.fetchone()[0]

def criar_usuario(username, email, senha_hash, nome):
    conexao = conectar()
    cursor = conexao.cursor()
    try:
        cursor.execute("""
            INSERT INTO usuarios (username, email, senha_hash, nome, criado_em, role)
            VALUES (?, ?, ?, ?, ?, 'usuario')
        """, (username, email, senha_hash, nome, datetime.now().strftime("%d/%m/%Y %H:%M")))
        conexao.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None

def buscar_usuario_por_username(username):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT id, username, email, senha_hash, nome, role FROM usuarios WHERE username = ?",
        (username,)
    )
    return cursor.fetchone()

def buscar_usuario_por_id(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT id, username, email, senha_hash, nome, role FROM usuarios WHERE id = ?",
        (usuario_id,)
    )
    return cursor.fetchone()

def listar_usuarios():
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, username, email, nome, role, criado_em
        FROM usuarios
        ORDER BY id ASC
    """)
    return cursor.fetchall()

def atualizar_role_usuario(usuario_id: int, novo_role: str):
    if novo_role not in ("admin", "usuario"):
        raise ValueError("role inválida: deve ser 'admin' ou 'usuario'")
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("UPDATE usuarios SET role = ? WHERE id = ?", (novo_role, usuario_id))
    conexao.commit()


MFA_MAX_TENTATIVAS = 3

def salvar_codigo_mfa(usuario_id: int, codigo: str, expira_em: datetime):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        UPDATE usuarios
        SET mfa_code = ?, mfa_expira = ?, mfa_tentativas = 0
        WHERE id = ?
    """, (codigo, expira_em.strftime("%d/%m/%Y %H:%M:%S"), usuario_id))
    conexao.commit()

def limpar_codigo_mfa(usuario_id: int):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        UPDATE usuarios
        SET mfa_code = NULL, mfa_expira = NULL, mfa_tentativas = 0
        WHERE id = ?
    """, (usuario_id,))
    conexao.commit()

def validar_codigo_mfa(usuario_id: int, codigo_digitado: str):
    """Retorna (sucesso: bool, mensagem: str)."""
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "SELECT mfa_code, mfa_expira, mfa_tentativas FROM usuarios WHERE id = ?",
        (usuario_id,)
    )
    resultado = cursor.fetchone()
    if resultado is None:
        return False, "Usuário não encontrado."

    codigo_salvo, expira_str, tentativas = resultado
    tentativas = tentativas or 0

    if not codigo_salvo or not expira_str:
        return False, "Nenhum código pendente. Faça login novamente."

    if tentativas >= MFA_MAX_TENTATIVAS:
        limpar_codigo_mfa(usuario_id)
        return False, "Número máximo de tentativas excedido. Faça login novamente."

    expira_em = datetime.strptime(expira_str, "%d/%m/%Y %H:%M:%S")
    if datetime.now() > expira_em:
        limpar_codigo_mfa(usuario_id)
        return False, "Código expirado. Faça login novamente."

    if codigo_digitado != codigo_salvo:
        cursor.execute(
            "UPDATE usuarios SET mfa_tentativas = mfa_tentativas + 1 WHERE id = ?",
            (usuario_id,)
        )
        conexao.commit()
        restantes = MFA_MAX_TENTATIVAS - (tentativas + 1)
        return False, f"Código incorreto. Tentativas restantes: {restantes}"

    limpar_codigo_mfa(usuario_id)
    return True, "Código validado com sucesso."



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

def listar_ativos_todos():
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT ativos.*, usuarios.username
        FROM ativos
        JOIN usuarios ON ativos.usuario_id = usuarios.id
        ORDER BY ativos.id DESC
    """)
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


def salvar_ativo_cloud(usuario_id, nome, ambiente, criticidade, score, analise,
                        aws_role_arn, aws_region):
    """
    Salva um ativo do tipo 'Conta Cloud (AWS)'. Diferente dos demais tipos,
    nao ha 'url' tradicional - o identificador do recurso escaneado e o
    ARN da IAM Role assumida via AssumeRole. Nao ha credenciais de longa
    duracao armazenadas (sem Access Key / Secret Key).
    """
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT INTO ativos (
            usuario_id, nome, tipo, url, ambiente, criticidade, score, analise,
            ultima_analise, aws_role_arn, aws_region
        ) VALUES (?, ?, 'Conta Cloud (AWS)', ?, ?, ?, ?, ?, ?, ?, ?)
    """, (usuario_id, nome, aws_role_arn, ambiente, criticidade, score, analise,
          datetime.now().strftime("%d/%m/%Y %H:%M"),
          aws_role_arn, aws_region))
    conexao.commit()

def buscar_role_arn_aws(usuario_id, ativo_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT aws_role_arn, aws_region
        FROM ativos WHERE id = ? AND usuario_id = ?
    """, (ativo_id, usuario_id))
    return cursor.fetchone()