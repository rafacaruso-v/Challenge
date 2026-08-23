Alguns pontos importantes. Para o código funcionar corretamente, vc deve baixar algumas ferramentas.

Abra o CMD do Windows e baixe todas as bibliotecas no requirements.txt

(Escreva pip install e instale todos de uma vez, ou se quiser um por um.)

Ex: pip install streamlit

-----------------------------------------------------------------------------------------------------

Depois que tiver tudo instalado, é só clonar o repositório no VS Code.

Para iniciar no VS Code, clique no código app.py e abra um terminal. 
Depois é so colar o código abaixo e uma página Web deve abrir:

python -m streamlit run app.py

-----------------------------------------------------------------------------------------------------

Para subir tudo no repositório do GitHub, use os seguintes comandos:

git add .
git commit -m "blablabla" (dentro das aspas voce coloca uma mensagem dizendo as mudanças que fez.)
git push origin main

-----------------------------------------------------------------------------------------------------

No final do projeto, vamos poder subir o docker.

docker compose up --build

-----------------------------------------------------------------------------------------------------


do que se trata cada arquivo

1.webhook.py (API)

Ele é o arquivo que se conecta com o banco de dados (db.py) e com o modelo de machine learning 
(risk_score_model).

Ele recebe do método do POST com o caminho /webhook/pr-scan os resultados das ferramentas como 
Semgrep, Trivy, Checkov, Gitleaks e DLP. Ele valida a key da API, salva e atualiza o ativo e o 
componente no banco e manda os números de vulnerabilidades pra poder realizar o cálculo do score.

no geral, ele é a entrada do CI/CD na nossa ASPM, retornando o score, criticidade, ativo_id e o componente_id.

2.auth.py (Auth)

conecta o db.py e com o email_service.py

Ele se trata da autenticação do usuário. o usuário fornece o user e a senha e o auth valida a senha e chama 
o email_service para enviar o código MFA (tipo um token de autenticação), então valida o código e o usuário 
loga na sessão.

Ele é usado para cuidar do cadastro, login, MFA, sessão e logout.

3.crypto.py (Auth)

é conectado com as variáveis de ambiente (CREDENTIALS_ENCRYPTION_KEY).  

Ele utiliza do metódo get_fernet() para criptografar (encrypt_value) e descriptografar (decrypt_value) valores
e serve para proteger as credenciais e os dados sensíveis que são armazenados.

4.email_service.py (Auth)

Ele se conecta com o google via SMTP (sigla para Simple Mail Transfer Protocol).

Esse arquivo pega o GMAIL_USER e o GMAIL_APP_PASSWORD digitado, conecta em smtp.gmail.com:465 e envia o código
MFA. É usado de forma resumida para enviar o código de verificação via e-mail, sendo importado pelo auth.py.

5.account_checks.py (CloudAws)

conecta o cspm.py à AWS IAM, consultando a política de senha da conta e o MFA do root. 
serve para verificar as configurações de segurança da conta AWS.

6.client.py (CloudAws)

esse arquivo usa o boto3 (uma biblioteca de python para AWS) e o STS (Security Token Service) que é o serviço da 
AWS que gera credenciais de segurança temporária junto ao comando AssumeRole (stsassumerole) que permite que o 
usuário empreste as permissões de um perfil (IAM Role) para terminar uma tarefa específica, fazendo a prática
de uso de menor privilégio. 

ele serve pra criar uma sessão autneticada na AWS para os outros checks poderem consultar os recursos lá.

7.cspm.py (CloudAws)

é o arquivo base para todos os outros. Ele chama o client.py para entrar na AWS e depois distribui a sessão para os outros arquivos
(s3_checks, iam_checks, ec2_checks, account_checks e inventory), servindo para executar o scan CSPM e devolver os achados + inventário.

8.s3_checks.py (CloudAws)

Conversa com a cspm, recebendo a sessão e consulta buckets, policies, ACls, criptografia e versionamento, Serve para
encontrar problemas de segurança nos buckets, exemplo, um acesso público ou a falta de criptografia.

9.iam_checks.py (CloudAws)

Conecta i AWS IAM ao cspm.py, consultando usuários, políticas, MFA e Access Keys. Ele serve para encontrar problemas de
identidade e acesso, como AdministratorAccess, ausência de MFA e chaves desatualizadas.

10. ec2_checks.py (CloudAws)

conecta o cspm a AWS EC2. Ele consulta o security groups e é usado para encontrar as portas sensíveis.

11.inventory.py (CloudAws)

ele conecta o arquivo cspm.py ao AWS S3/IAM/EC2, que são em ordem: serviço de armazenamento de arquivos/objetos;
serviço de gerenciamente de identidades e acessos; serviço de servidores virtuais.
É usado para montar o inventário da conta, como buckets, usuários, Security Groups e instâncias EC2.

12.avaliador.py (Compliance)

utiliza dos comandos avaliar_acesso_logico(), avaliar_mitigacao_vulnerabilidades(), avaliar_rastreabilidade, avaliar_avaliacao_riscos()
onde, em ordem do primeiro ao último:

verifica MFA e RBAC dos usuários da plataforma;
verifica se os ativos possuem análises/scanners (DAST,SAST,CSPM, etc);
verifica se existem logs de auditoria recentes;
verifica se os ativos possuem score de risco calculado.

ao final, tudo é juntado na funçao avaliar_plataforma(usuario_id) e exibido como "Conforme", "Parcialmente conforme",
"Não conforme" ou "Não avaliado".

13. db.py (Database)

se trata do banco de dados do projeto, onde tudo é salvo, seja login, score, api_keys ou usuários com controle de papéis
(admin ou user).

14. gemini.py (LLMS)

conecta com a IA do google, scanners de segurança e módulos de machine learning, recebendo os resultados do Semgrep, Trivy, Zap, Checkov, Gitleaks e DLP, daí
monta um prompt e envia para o modelo Gemini 2.5 Flash; depois processa o json retornado.
serve pra fazer uma análise inteligente das vulnerabilidades, classificando a criticidade, score, falsos positivos e gerando uma explicação ou recomendações.

15. sugestoes.py (LLMS)

busca no banco os Ativos e componentes do usuário, envia os identificadores para o gemini e recebe as sugestões, depois grava essas sugestões no banco 
no metódo salvar_sugestao_agrupamento(). o sugestoes.py serve pra descobrir se os repositórios e os componentes Cloud pertencem ao mesmo sistema, sugerindo
vinculações ou a criaçar de um novo Ativo.

16. anomaly_detector.py (MachineLearning)

se conecta com o banco de dados e NumPy

busca o histório de scores de um componente no banco e com poucos dados usa Isolation Fores +Z-score para comparar o score atual com os antigos.
o arquivo serve pra detectar as mudanças "estranhas" no score de segurança de um componente, como um aumento anormal ou um comportamento muito
diferente do histórico.

17. false_positive.py (MachineLearning)

se conecta com o resultado dos scanners SAST, DAST, CSPM, SCA, e IaC e Scikit-learn.
ele transforma cada finding em características, como entropia, tamanho do token, caminho do arquivo e palavras de teste/produção. Com isso, um random forest classifier
calcula a probabilidade de ser falso positivo.
Em geralm serve para reduzir os falsos positivos automaticamente, descartando findings quando a probabilidade calculada chega a pelo menos 95%.

18.risk_score_model (MachineLearning)

ele conversa com o gemini.py, NumPy e a biblioteca Scikit-learn.

recebe a quantidade de cada tipo de vulnerabilidades (Críticas, Altas, Médias e Baixas) e passa esses dados
por um Random Forest Regressor, gerando um score de 0 até 100.

é usado pra calcular automaticamente o score de risco do ativo e depois classificar esse score em Baixa, Média, Alta ou Crítica.


19.monitor.py (Monitoring)

se conecta ao banco de dados, scanners de segurança, gemini.py, false_positive.py e anomaly_detector.py

esse arquivo executa o re-scan dos componentes, chamando os scanners mais adequados para cada tipo (Cloud, Repositório, API ou Aplicação). 
os resultados passam pelos filtros de falso positivos e pela IA (gemini), depois o componente é atualizado no banco e o histórico é registrado.

ele é a "base" do monitoramento autmático, sendo o responsável por verificar os componentes, atualizar scores/criticidades, detectar anomalias,
verificar disponibilidade de URLs e gerar sugestões de agrupamento.

20.scheduler.py (Monitoring)

se conecta ao monitor.py e ao db.py

faz uso da biblioteca schedule pra criar uma tarefa que chama a função rescan_automatico() em um intervalo que é definido no banco. Executa o agendamento em uma
thread separada pra evitar travamento.

serve pra automatizar o re-scan de tempos em tempos sem precisar executar toda hora o monitoramento

21. threat_intelligence.py (Monitoring)

faz uso da API do NVD, para consultar CVEs (vulnerabilidades e exposições comuns).

ele realiza um requisição http para a API do NVD buscando os CVEs publicados nos últimos dias, e extrai informações delas como IDs, descrição, CVSS, severidade, produtos e datas.

serve pra trazer informações recentes de vulnerabilidades externas, funcionando como fonte de Threat Intelligence.

22. assistant.py (NLP)

fala com o banco e com o threat_intelligence.py

ele identifica o tipo de pergunta do usuário e busca os dados necessários no banco ou no API de CVEs. Depois ele
monta um prompt contextualizado para o Gemini

serve pra ser a camada de inteligência/contexto do projeto para o chatbot, garantindo que a IA responda com base nos ativos, alertas, vulnerabilidades e CVEs reais da plataforma.


23.nlp.py (NLP)

fala com o assistant.py, Streamlit, Gemini API e arquivos enviados pelo usuário.

é o responsável por criar a interface do chatbot no streamlit e mantém o histórico da conversa e envia para o gemini, seja o prompt preparado
pelo assistant.py quanto imagens/pdfs/arquivos anexados nele.

serve para ser a interface do chatbot, permitindo falar com a IA e consultar os dados de segurança da plataforma em linguagem mais neutra.

24.Checkov.py (Scanners)

é o scanner responsável por analisar Infrastructure as Code (IaC)

serve pra encontrar configurações inseguras na infreaestrutura definidas em código. se conecta ao Terraform Runner e ao CloudFormation Runner.

25.dlp.py (Scanners)

É o scanner de dados sensíveis/PII e serve para detectar informações sensíveis que podem ter sido escritas acidentalmente no código, como cpf, cnpj, cartão ou email, mascarando os valores encontrados.

26.gitleaks.py (Scanners)

é o scanner que pega o repositório de código, vasculha arquivo por arquivo procurando padrões de senhas, transforma em json e mascara API kets, tokens, credenciais, chaves expostas, isto é, ele se difere do 
DLP porque enquanto o DLP mascara dados pessoais das pessoas, ele procura por "técnicas" no código.

27.owaspzap.py (Scanners)

é o módulo que integra o OWASP ZAP para testar as aplicações que estão rodando, testando a aplicação em execução, e não somente os arquivos do projeto (como o Semgrep, Trivy e o Checkov fazem)

ele funciona da seguinte forma, a url da aplicação passa no OWASP ZAP, que passa depois no Spider, também no ajax spider, e por último passa no Active Scan e retorna as vulnerabilidades.
O spider encontra as páginas/endpoints, o Ajax ajuda a encontrar os conteúdos que dependem do javascript e o Active Scan testa a aplicação

28.repo_utils.py (Scanners)

serve pra evitar que cada scanner faça seu próprio clone, isto é, o Semgrep execute o git clone, o Trivy execute o git clone e o checkov execute o git clone, para evitar toda hora
de perder tempo instalando na internet e redirecionando para uma pasta temporária onde todos podem usar e é apagada ao final da execução.

29.semgrep.py (Scanners)

é o scanner de SAST (Static Application Security Testing)

é o responsável por analisar o código fone e procurar as vulnerabilidades e padrõess inseguros no código sem executar a aplicação.

30.Trivy.py (Scanners)

é o arquivo que integra o Trivy (Um scanner que procura brecha nas dependências, imagens de container, IaC e Secrets)

31.App.py

é onde fica localizado toda a interface baseada no streamlit

32.gerar_pdf.py

cria um PDF usando a biblioteca ReportLab e monta uma capa com o nome do ativo, tipo e ambiente, criticidade, risk score, data da análise, responsável e a URL/caminho.
também mostra quais as ferramentas de segurança que foram utilizadas, dependendo do tipo de ativo. Além disso, ele lê e separa as vulnerabilidades por categoria, isto é, SAST/DAST, SCA, CSPM, IaC, Secrets, DLP.
por fim, classifica as vuvlnerabilidades por urgência, cria cards pra cada uma encontrada, gera uma Declaração de Conformidade, avaliando os critéiros do SOC 2 e controles da ISO 27001 e usa a função avaliar_plataforma()
para buscar dados reais de compliance da plataforma.