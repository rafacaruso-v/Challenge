Alguns pontos importantes. Para o código funcionar corretamente, vc deve baixar algumas ferramentas.

Abra o CMD do Windows e digite os comandos abaixo, quando terminar um, prossiga para o próximo: 

pip install streamlit
pip install semgrep
pip install zaproxy
pip install google-genai
pip install plotly pandas
pip install streamlit-option-menu
pip install schedule
pip install streamlit-cookies-controller
pip install bcrypt

(Esse texto vai ser atualizado frequentemente conforme o trabalho aumenta para dizer o que deve ser baixado.)

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