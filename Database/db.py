import sqlite3
import bcrypt
import os
import secrets
from datetime import datetime

def conectar():
    conexao = sqlite3.connect("aspm.db", check_same_thread=False)
    conexao.execute("PRAGMA foreign_keys = ON")
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            chave TEXT UNIQUE NOT NULL,
            nome TEXT,
            criado_em TEXT NOT NULL,
            ultima_utilizacao TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    for sql in [
        "ALTER TABLE alertas ADD COLUMN usuario_id INTEGER",
        "ALTER TABLE historico ADD COLUMN usuario_id INTEGER",
        "ALTER TABLE logs ADD COLUMN nivel TEXT",
        "ALTER TABLE logs ADD COLUMN aplicacao TEXT",
        "ALTER TABLE logs ADD COLUMN ambiente TEXT",
        "ALTER TABLE logs ADD COLUMN origem TEXT",
        "ALTER TABLE usuarios ADD COLUMN role TEXT DEFAULT 'usuario'",
        "ALTER TABLE usuarios ADD COLUMN mfa_code TEXT",
        "ALTER TABLE usuarios ADD COLUMN mfa_expira TEXT",
        "ALTER TABLE usuarios ADD COLUMN mfa_tentativas INTEGER DEFAULT 0",
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

    _migrar_para_modelo_ativo_componente(conexao)
    _criar_estrutura_ativos_v2(conexao)
    _criar_view_resumo(conexao)

    criar_admin_padrao()


def _migrar_para_modelo_ativo_componente(conexao):

    cursor = conexao.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ativos'")
    tabela_ativos_existe = cursor.fetchone() is not None

    if not tabela_ativos_existe:
        return 

    cursor.execute("PRAGMA table_info(ativos)")
    colunas_ativos = {row[1] for row in cursor.fetchall()}

    schema_e_legado = "tipo" in colunas_ativos and "url" in colunas_ativos
    if not schema_e_legado:
        return

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ativos_old'")
    ja_migrado = cursor.fetchone() is not None
    if ja_migrado:
        return 

    cursor.execute("ALTER TABLE ativos RENAME TO ativos_old")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            nome TEXT NOT NULL,
            descricao TEXT,
            dono TEXT,
            criticidade_negocio TEXT,
            criado_em TEXT NOT NULL,
            atualizado_em TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ativo_componentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ativo_id INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            ambiente TEXT NOT NULL,
            url TEXT,
            aws_role_arn TEXT,
            aws_region TEXT,
            criticidade TEXT,
            score INTEGER,
            analise TEXT,
            ultima_analise TEXT,
            criado_em TEXT NOT NULL,
            FOREIGN KEY (ativo_id) REFERENCES ativos (id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_componentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            componente_id INTEGER NOT NULL,
            ativo_id INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL,
            score INTEGER,
            data TEXT NOT NULL,
            FOREIGN KEY (componente_id) REFERENCES ativo_componentes (id) ON DELETE CASCADE,
            FOREIGN KEY (ativo_id) REFERENCES ativos (id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        INSERT INTO ativos (id, usuario_id, nome, descricao, dono, criticidade_negocio, criado_em, atualizado_em)
        SELECT
            id,
            usuario_id,
            nome,
            NULL,
            NULL,
            NULL,
            COALESCE(ultima_analise, datetime('now')),
            ultima_analise
        FROM ativos_old
    """)

    cursor.execute("""
        INSERT INTO ativo_componentes (
            ativo_id, usuario_id, tipo, ambiente, url, aws_role_arn, aws_region,
            criticidade, score, analise, ultima_analise, criado_em
        )
        SELECT
            id, usuario_id, tipo, ambiente, url, aws_role_arn, aws_region,
            criticidade, score, analise,
            COALESCE(ultima_analise, datetime('now'))
        FROM ativos_old
    """)

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='historico_ativos'")
    if cursor.fetchone():
        cursor.execute("""
            INSERT INTO historico_componentes (componente_id, ativo_id, usuario_id, score, data)
            SELECT
                c.id, c.ativo_id, c.usuario_id, h.score, h.data
            FROM historico_ativos h
            JOIN ativo_componentes c ON c.ativo_id = h.ativo_id
        """)

    conexao.commit()


def _criar_estrutura_ativos_v2(conexao):
    """
    Garante que as tabelas do modelo novo existam mesmo em um banco criado
    do zero (sem nunca ter passado pelo schema legado).
    """
    cursor = conexao.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ativos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            nome TEXT NOT NULL,
            descricao TEXT,
            dono TEXT,
            criticidade_negocio TEXT,
            criado_em TEXT NOT NULL,
            atualizado_em TEXT,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ativo_componentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ativo_id INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL,
            tipo TEXT NOT NULL CHECK (tipo IN ('Repositório', 'API', 'Aplicação', 'Conta Cloud (AWS)')),
            ambiente TEXT NOT NULL,
            url TEXT,
            aws_role_arn TEXT,
            aws_region TEXT,
            criticidade TEXT,
            score INTEGER,
            analise TEXT,
            ultima_analise TEXT,
            criado_em TEXT NOT NULL,
            FOREIGN KEY (ativo_id) REFERENCES ativos (id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS historico_componentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            componente_id INTEGER NOT NULL,
            ativo_id INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL,
            score INTEGER,
            data TEXT NOT NULL,
            FOREIGN KEY (componente_id) REFERENCES ativo_componentes (id) ON DELETE CASCADE,
            FOREIGN KEY (ativo_id) REFERENCES ativos (id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_componentes_ativo ON ativo_componentes(ativo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_componentes_usuario ON ativo_componentes(usuario_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_historico_comp_data ON historico_componentes(componente_id, data)")

    conexao.commit()


def _criar_view_resumo(conexao):
    """
    View com o score/criticidade agregados por ativo, seguindo a regra
    'pior caso': se qualquer componente do ativo for Critico, o ativo
    aparece como Critico no resumo (e assim por diante, em ordem de
    severidade). Isso reflete que um atacante so precisa de 1 ponto fraco
    para comprometer a aplicacao inteira.
    """
    cursor = conexao.cursor()
    cursor.execute("DROP VIEW IF EXISTS vw_ativos_resumo")
    cursor.execute("""
        CREATE VIEW vw_ativos_resumo AS
        SELECT
            a.id,
            a.usuario_id,
            a.nome,
            a.descricao,
            a.dono,
            a.criticidade_negocio,
            COUNT(c.id) AS total_componentes,
            MIN(CASE WHEN c.criticidade != 'Erro' THEN c.score END) AS score_minimo,
            MAX(CASE WHEN c.criticidade != 'Erro' THEN c.score END) AS score_maximo,
            ROUND(AVG(CASE WHEN c.criticidade != 'Erro' THEN c.score END), 0) AS score_medio,
            CASE
                WHEN SUM(CASE WHEN c.criticidade = 'Crítica' THEN 1 ELSE 0 END) > 0 THEN 'Crítica'
                WHEN SUM(CASE WHEN c.criticidade = 'Alta'    THEN 1 ELSE 0 END) > 0 THEN 'Alta'
                WHEN SUM(CASE WHEN c.criticidade = 'Média'   THEN 1 ELSE 0 END) > 0 THEN 'Média'
                WHEN SUM(CASE WHEN c.criticidade = 'Baixa'   THEN 1 ELSE 0 END) > 0 THEN 'Baixa'
                ELSE 'Sem análise'
            END AS criticidade_agregada,
            MAX(c.ultima_analise) AS ultima_analise
        FROM ativos a
        LEFT JOIN ativo_componentes c ON c.ativo_id = a.id
        GROUP BY a.id
    """)
    conexao.commit()


def criar_admin_padrao():
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_email    = os.environ.get("ADMIN_EMAIL")
    admin_senha    = os.environ.get("ADMIN_PASSWORD")

    if not admin_username or not admin_email or not admin_senha:
        return

    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT id FROM usuarios WHERE username = ?", (admin_username,))
    resultado = cursor.fetchone()

    if resultado:
        admin_id = resultado[0]
    else:
        senha_hash = bcrypt.hashpw(admin_senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor.execute("""
            INSERT INTO usuarios (username, email, senha_hash, nome, criado_em, role)
            VALUES (?, ?, ?, ?, ?, 'admin')
        """, (admin_username, admin_email, senha_hash, "Administrador",
              datetime.now().strftime("%d/%m/%Y %H:%M")))
        conexao.commit()
        admin_id = cursor.lastrowid

    chave_fixa = os.environ.get("API_KEY")
    if chave_fixa:
        garantir_api_key_fixa(admin_id, chave_fixa, "Integração CI/CD (fixa via .env)")


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


def gerar_api_key(usuario_id: int, nome: str = "Integração CI/CD") -> str:
    conexao = conectar()
    cursor = conexao.cursor()

    chave = f"aspm_{secrets.token_urlsafe(32)}"

    cursor.execute("""
        INSERT INTO api_keys (usuario_id, chave, nome, criado_em)
        VALUES (?, ?, ?, ?)
    """, (usuario_id, chave, nome, datetime.now().strftime("%d/%m/%Y %H:%M")))
    conexao.commit()

    return chave

def garantir_api_key_fixa(usuario_id: int, chave_fixa: str, nome: str = "Integração CI/CD"):
    if not chave_fixa or not chave_fixa.startswith("aspm_"):
        return

    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO api_keys (usuario_id, chave, nome, criado_em)
        VALUES (?, ?, ?, ?)
    """, (usuario_id, chave_fixa, nome, datetime.now().strftime("%d/%m/%Y %H:%M")))
    conexao.commit()

def validar_api_key(chave: str):
    if not chave or not chave.startswith("aspm_"):
        return None

    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT usuario_id FROM api_keys WHERE chave = ?", (chave,))
    resultado = cursor.fetchone()

    if resultado is None:
        return None

    cursor.execute(
        "UPDATE api_keys SET ultima_utilizacao = ? WHERE chave = ?",
        (datetime.now().strftime("%d/%m/%Y %H:%M:%S"), chave)
    )
    conexao.commit()

    return resultado[0]

def listar_api_keys(usuario_id: int):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, chave, nome, criado_em, ultima_utilizacao
        FROM api_keys WHERE usuario_id = ?
        ORDER BY id DESC
    """, (usuario_id,))
    linhas = cursor.fetchall()

    return [
        {
            "id": r[0],
            "chave_mascarada": f"...{r[1][-6:]}",
            "nome": r[2],
            "criado_em": r[3],
            "ultima_utilizacao": r[4],
        }
        for r in linhas
    ]

def revogar_api_key(usuario_id: int, api_key_id: int):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute(
        "DELETE FROM api_keys WHERE id = ? AND usuario_id = ?",
        (api_key_id, usuario_id)
    )
    conexao.commit()


def criar_ativo(usuario_id, nome, descricao=None, dono=None, criticidade_negocio=None):
    """
    Cria o Ativo pai (sem nenhum componente ainda). Retorna o id gerado,
    que deve ser usado em seguida para adicionar componentes com
    adicionar_componente().
    """
    conexao = conectar()
    cursor = conexao.cursor()
    agora = datetime.now().strftime("%d/%m/%Y %H:%M")
    cursor.execute("""
        INSERT INTO ativos (usuario_id, nome, descricao, dono, criticidade_negocio, criado_em, atualizado_em)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (usuario_id, nome, descricao, dono, criticidade_negocio, agora, agora))
    conexao.commit()
    return cursor.lastrowid

def atualizar_ativo(usuario_id, ativo_id, nome=None, descricao=None, dono=None, criticidade_negocio=None):
    if nome is None and descricao is None and dono is None and criticidade_negocio is None:
        return

    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        UPDATE ativos
        SET nome = COALESCE(?, nome),
            descricao = COALESCE(?, descricao),
            dono = COALESCE(?, dono),
            criticidade_negocio = COALESCE(?, criticidade_negocio),
            atualizado_em = ?
        WHERE id = ? AND usuario_id = ?
    """, (
        nome, descricao, dono, criticidade_negocio,
        datetime.now().strftime("%d/%m/%Y %H:%M"),
        ativo_id, usuario_id
    ))
    conexao.commit()

def listar_ativos_db(usuario_id):
    """
    Retorna os Ativos (pais) do usuário já com criticidade/score agregados
    a partir dos componentes (regra 'pior caso'), via vw_ativos_resumo.

    Colunas retornadas, nesta ordem:
    0: id                    5: total_componentes
    1: usuario_id            6: score_minimo
    2: nome                  7: score_maximo
    3: descricao             8: score_medio
    4: dono                  9: criticidade_negocio
                              10: criticidade_agregada
                              11: ultima_analise
    """
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, usuario_id, nome, descricao, dono, total_componentes,
               score_minimo, score_maximo, score_medio, criticidade_negocio,
               criticidade_agregada, ultima_analise
        FROM vw_ativos_resumo
        WHERE usuario_id = ?
        ORDER BY id DESC
    """, (usuario_id,))
    return cursor.fetchall()

def buscar_ativo(usuario_id, ativo_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, usuario_id, nome, descricao, dono, total_componentes,
               score_minimo, score_maximo, score_medio, criticidade_negocio,
               criticidade_agregada, ultima_analise
        FROM vw_ativos_resumo
        WHERE usuario_id = ? AND id = ?
    """, (usuario_id, ativo_id))
    return cursor.fetchone()

def buscar_ativo_por_nome(usuario_id, nome):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id FROM ativos
        WHERE usuario_id = ? AND nome = ?
        LIMIT 1
    """, (usuario_id, nome))
    resultado = cursor.fetchone()
    return resultado[0] if resultado else None

def listar_ativos_todos():
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT r.id, r.usuario_id, r.nome, r.descricao, r.dono, r.total_componentes,
               r.score_minimo, r.score_maximo, r.score_medio, r.criticidade_negocio,
               r.criticidade_agregada, r.ultima_analise, usuarios.username
        FROM vw_ativos_resumo r
        JOIN usuarios ON r.usuario_id = usuarios.id
        ORDER BY r.id DESC
    """)
    return cursor.fetchall()

def deletar_ativo(usuario_id, ativo_id):
    """
    Remove o ativo e, em cascata (via FOREIGN KEY ... ON DELETE CASCADE),
    todos os seus componentes e o histórico associado.
    """
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("SELECT nome FROM ativos WHERE id = ? AND usuario_id = ?", (ativo_id, usuario_id))
    resultado = cursor.fetchone()
    cursor.execute("DELETE FROM ativos WHERE id = ? AND usuario_id = ?", (ativo_id, usuario_id))
    if resultado:
        cursor.execute("DELETE FROM alertas WHERE ativo_nome = ? AND usuario_id = ?", (resultado[0], usuario_id))
    conexao.commit()


def adicionar_componente(
    usuario_id, ativo_id, tipo, ambiente,
    url=None, criticidade=None, score=None, analise=None,
    aws_role_arn=None, aws_region=None
):
    """
    Vincula um novo componente técnico a um Ativo já existente. Pode ser
    chamado quantas vezes for preciso para o mesmo ativo_id (ex: repo +
    instância de produção + instância de homologação).
    """
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT INTO ativo_componentes (
            ativo_id, usuario_id, tipo, ambiente, url, aws_role_arn, aws_region,
            criticidade, score, analise, ultima_analise, criado_em
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ativo_id, usuario_id, tipo, ambiente, url, aws_role_arn, aws_region,
        criticidade, score, analise,
        datetime.now().strftime("%d/%m/%Y %H:%M"),
        datetime.now().strftime("%d/%m/%Y %H:%M"),
    ))
    conexao.commit()
    return cursor.lastrowid

def atualizar_componente(usuario_id, componente_id, criticidade, score, analise):
    """Atualiza o resultado de uma nova análise/scan sobre um componente
    já existente (ex: re-scan agendado)."""
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        UPDATE ativo_componentes
        SET criticidade = ?, score = ?, analise = ?, ultima_analise = ?
        WHERE id = ? AND usuario_id = ?
    """, (
        criticidade, score, analise,
        datetime.now().strftime("%d/%m/%Y %H:%M"),
        componente_id, usuario_id
    ))
    conexao.commit()

def listar_componentes(usuario_id, ativo_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, ativo_id, usuario_id, tipo, ambiente, url, aws_role_arn, aws_region,
               criticidade, score, analise, ultima_analise, criado_em
        FROM ativo_componentes
        WHERE usuario_id = ? AND ativo_id = ?
        ORDER BY id ASC
    """, (usuario_id, ativo_id))
    return cursor.fetchall()

def listar_componentes_usuario(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT c.id, c.ativo_id, c.usuario_id, c.tipo, c.ambiente, c.url,
               c.aws_role_arn, c.aws_region, c.criticidade, c.score, c.analise,
               c.ultima_analise, c.criado_em, a.nome AS ativo_nome
        FROM ativo_componentes c
        JOIN ativos a ON a.id = c.ativo_id
        WHERE c.usuario_id = ?
        ORDER BY c.id DESC
    """, (usuario_id,))
    return cursor.fetchall()

def buscar_componente(usuario_id, componente_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT c.id, c.ativo_id, c.usuario_id, c.tipo, c.ambiente, c.url,
               c.aws_role_arn, c.aws_region, c.criticidade, c.score, c.analise,
               c.ultima_analise, c.criado_em, a.nome AS ativo_nome
        FROM ativo_componentes c
        JOIN ativos a ON a.id = c.ativo_id
        WHERE c.usuario_id = ? AND c.id = ?
    """, (usuario_id, componente_id))
    return cursor.fetchone()


def buscar_role_arn_aws(usuario_id, componente_id):
    """Agora busca pelo id do COMPONENTE (não mais do ativo pai), já que o
    ARN/região vivem em ativo_componentes."""
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT aws_role_arn, aws_region
        FROM ativo_componentes WHERE id = ? AND usuario_id = ?
    """, (componente_id, usuario_id))
    return cursor.fetchone()

def registrar_historico(usuario_id):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT score FROM ativo_componentes
        WHERE usuario_id = ? AND criticidade != 'Erro' AND score IS NOT NULL
    """, (usuario_id,))
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


def registrar_historico_componente(usuario_id, componente_id, ativo_id, score):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        INSERT INTO historico_componentes (componente_id, ativo_id, usuario_id, score, data)
        VALUES (?, ?, ?, ?, ?)
    """, (componente_id, ativo_id, usuario_id, score, datetime.now().strftime("%d/%m/%Y %H:%M:%S")))
    conexao.commit()

def listar_historico_componente(usuario_id, componente_id, limite=50):
    conexao = conectar()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT score, data FROM historico_componentes
        WHERE usuario_id = ? AND componente_id = ?
        ORDER BY id ASC
        LIMIT ?
    """, (usuario_id, componente_id, limite))
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