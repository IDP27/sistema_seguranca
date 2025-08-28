📖 Sistema de Gerenciamento de Segurança

Este projeto é um sistema de controle de acesso e gerenciamento de recursos feito com FastAPI (backend) + HTML/CSS/JS (frontend).
Ele permite cadastrar usuários com diferentes papéis (FUNCIONÁRIO, GERENTE, SECURITY_ADMIN) e aplicar regras de acesso, registrar logs e administrar recursos.

⚙️ Tecnologias usadas
	•	Backend: FastAPI + SQLAlchemy + JWT (python-jose)
	•	Banco: SQLite (padrão, mas adaptável para PostgreSQL)
	•	Frontend: HTML + CSS + JavaScript puro
	•	Autenticação: JWT + RBAC (Role-Based Access Control)

 📦 Instalação do Backend

1. Clonar o repositório:
1.1. -> (bash)git clone https://github.com/IDP27/sistema_seguranca.git
cd sistema_seguranca

2. Criar e ativar ambiente virtual:
2.2.-> (bash)python -m venv .venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate      # Windows


3. Instalar dependências:
3.3 -> (bash) pip install -r requirements.txt


4. Rodar a API:
4.4 -> (bash) uvicorn app.main:app --reload --port 8005



5. ✅ O servidor estará disponível em:
	•	API docs → http://127.0.0.1:8005/docs


6.👤 Usuário inicial (seed)

Na primeira execução, o sistema cria automaticamente o usuário admin:

6.6 -> Usuário: admin
Senha:   admin123
Role:    SECURITY_ADMIN.
(OBS) -> Esse usuário é necessário para criar os demais.


🖥️ Frontend

1. Abrir a interface

Abra o arquivo index.html diretamente no navegador (duplo clique).

2. Tela de login
	•	Preencha:
	•	Usuário: admin
	•	Senha: admin123
	•	API base: http://127.0.0.1:8005

	•	Preencha:
	•	Usuário: admin
	•	Senha: admin123
	•	API base: http://127.0.0.1:8005
	•	Clique em Entrar.

3. Dashboard

Após login, você verá:
	•	Visão Geral → estatísticas de acessos, usuários ativos, recursos.
	•	Controle de Acesso → tentar entrar em áreas permitidas.
	•	Recursos → CRUD de recursos (estoque, equipamentos etc).
	•	Logs → registros de entradas (apenas admin).
	•	Usuários → CRUD de usuários (apenas admin).


 👥 Papéis de Usuários (Roles)
	•	FUNCIONÁRIO (EMPLOYEE)
	•	Pode acessar apenas recepcao e escritorio1.
	•	Não consegue criar recursos nem ver logs.
	•	GERENTE (MANAGER)
	•	Pode acessar as áreas do funcionário + gerencia e sala_reuniao.
	•	Pode criar e editar recursos.
	•	Não consegue ver usuários.
	•	ADMINISTRADOR DE SEGURANÇA (SECURITY_ADMIN)
	•	Acesso total a todas as áreas.
	•	Pode gerenciar usuários e logs.
	•	Pode resetar o sistema.


 🔑 Fluxo de uso

1. Criar novos usuários

Estando logado como admin:
	•	Vá em Usuários → Novo Usuário.
	•	Preencha username, senha, escolha a role (EMPLOYEE, MANAGER ou SECURITY_ADMIN).
	•	Salve.

2. Login com outro usuário
	•	Clique em Sair.
	•	Entre com as credenciais do novo usuário.


3. Acessar áreas
	•	Vá em Controle de Acesso.
	•	Selecione uma área e clique em Acessar Área.
	•	Resultado será Permitido ou Negado, gerando um log.


4. Gerenciar recursos
	•	Acesse Recursos.
	•	Apenas GERENTE e SECURITY_ADMIN podem criar/editar/deletar recursos.


5. Consultar logs
	•	Acesse Logs.
	•	Apenas SECURITY_ADMIN pode visualizar e apagar registros.

📊 Rotas principais (API)

🔐 Autenticação
	•	POST /auth/login → login, retorna JWT.
	•	POST /auth/register → criar novo usuário (apenas admin).
	•	POST /auth/logout → logout (token não é mais usado).

👥 Usuários
	•	GET /users/me → dados do usuário logado.
	•	GET /users → listar usuários (admin).
	•	PUT /users/{id} → atualizar usuário (admin).
	•	DELETE /users/{id} → remover usuário (admin).

🚪 Áreas
	•	GET /areas/allowed → lista de áreas acessíveis ao usuário.
	•	POST /areas/{area}/enter → tenta entrar em área → gera log.

 📝 Logs
	•	GET /logs → listar registros (admin).
	•	DELETE /logs → apagar todos os registros (admin).

📦 Recursos
	•	GET /resources → listar recursos (com filtros e paginação).
	•	POST /resources → criar recurso (manager/admin).
	•	PUT /resources/{id} → editar recurso (manager/admin).
	•	DELETE /resources/{id} → deletar recurso (manager/admin).

📈 Estatísticas
	•	GET /stats/overview → acessos hoje, usuários ativos, recursos totais, usuários totais.


 🧪 Testando pelo Postman

1. Login admin

1.1 -> POST http://127.0.0.1:8005/auth/login
Body JSON:
{ "username": "admin", "password": "admin123" }

2. Criar usuário gerente

2.2 -> POST http://127.0.0.1:8005/auth/register
Headers: Authorization: Bearer <TOKEN_ADMIN>
Body JSON:
{ "username": "maria", "password": "123456", "role": "MANAGER" }

3. Login gerente.

3.3 -> POST http://127.0.0.1:8005/auth/login
{ "username": "maria", "password": "123456" }

🔄 Reset do sistema (modo dev)

Se quiser limpar todos os dados e voltar ao estado inicial (apenas admin criado):
DELETE http://127.0.0.1:8005/dev/reset (APENAS PARA TESTES)

📌 Resumo da interação do usuário
	1.	Abrir o index.html no navegador.
	2.	Logar como admin (admin / admin123).
	3.	Criar usuários com diferentes roles.
	4.	Sair e entrar como funcionário ou gerente.
	5.	Tentar acessar áreas → ver permissões e logs.
	6.	Criar e gerenciar recursos (se gerente/admin).
	7.	Consultar estatísticas e registros (se admin).


 



   
