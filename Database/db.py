import sqlite3

# =========================================
# CONEXÃO COM BANCO
# =========================================

def conectar():
    conexao = sqlite3.connect(
        "aspm.db",
        check_same_thread=False
    )
    return conexao

# =========================================
# CRIAR TABELA
# =========================================

def criar_tabela():
    conexao = conectar()
    cursor = conexao.cursor()
    
    # Adicionada a coluna 'analise TEXT' no final
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            tipo TEXT,
            url TEXT,
            ambiente TEXT,
            criticidade TEXT,
            score INTEGER,
            analise TEXT
        )
        """
    )
    conexao.commit()

# =========================================
# SALVAR ATIVO
# =========================================

# Adicionado o parâmetro 'analise'
def salvar_ativo(nome, tipo, url, ambiente, criticidade, score, analise):
    conexao = conectar()
    cursor = conexao.cursor()
    
    # Adicionado 'analise' no INSERT e mais um '?' nos VALUES
    cursor.execute(
        """
        INSERT INTO ativos (
            nome,
            tipo,
            url,
            ambiente,
            criticidade,
            score,
            analise
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            nome,
            tipo,
            url,
            ambiente,
            criticidade,
            score,
            analise
        )
    )
    conexao.commit()

# =========================================
# LISTAR ATIVOS
# =========================================

def listar_ativos_db():
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT * FROM ativos")
    ativos = cursor.fetchall()
    return ativos