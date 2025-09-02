from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# URL de conexão com o banco de dados
# Usando SQLite local, criando um arquivo chamado 'app.db' na raiz do projeto.
SQLALCHEMY_DATABASE_URL = "sqlite:///./app.db"

# Cria o engine de conexão com o banco de dados.
# - connect_args={"check_same_thread": False} é necessário apenas para SQLite
#   pois, por padrão, ele não permite múltiplas threads acessando a mesma conexão.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Cria a fábrica de sessões para interagir com o banco de dados.
# - autocommit=False: evita commits automáticos, dando mais controle.
# - autoflush=False: evita sincronização automática antes de queries.
# - bind=engine: conecta a sessão ao engine configurado acima.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Classe base para todos os modelos ORM.
# Cada modelo (User, AccessLog, Resource, etc.) herdará de Base.
Base = declarative_base()