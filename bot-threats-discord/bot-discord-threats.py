import discord
from discord.ext import tasks
import feedparser
import os
import asyncio
import aiohttp
import io
import re
import sqlite3
from dotenv import load_dotenv
from datetime import datetime

# Carregar variáveis de ambiente
load_dotenv()

DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_ID = os.getenv('DISCORD_CHANNEL_ID')

# Imagem padrão caso a notícia não tenha imagem (Cyber Threat Alert)
DEFAULT_IMAGE_URL = "https://placehold.co/600x400/1a1a1a/e31010.png?text=CYBER+THREAT+ALERT"

# Configuração dos Feeds (Fontes Públicas)
# Você pode adicionar mais feeds RSS aqui
FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews", # The Hacker News
    "https://www.cisa.gov/uscert/ncas/alerts.xml", # US-CERT CISA Alerts
    "https://krebsonsecurity.com/feed/",           # Krebs on Security
]

class ThreatBot(discord.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.first_run = True
        self.init_db()

    def init_db(self):
        try:
            with sqlite3.connect('threats.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sent_alerts (
                        id TEXT PRIMARY KEY,
                        date_sent TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
        except Exception as e:
            print(f"Erro ao inicializar banco de dados: {e}")

    def is_alert_sent(self, entry_id):
        try:
            with sqlite3.connect('threats.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM sent_alerts WHERE id = ?', (entry_id,))
                return cursor.fetchone() is not None
        except Exception as e:
            print(f"Erro ao verificar banco de dados: {e}")
            return False

    def mark_alert_sent(self, entry_id):
        try:
            with sqlite3.connect('threats.db') as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR IGNORE INTO sent_alerts (id) VALUES (?)', (entry_id,))
                conn.commit()
        except Exception as e:
            print(f"Erro ao salvar no banco de dados: {e}")

    async def setup_hook(self):
        # Iniciar a tarefa de loop em background
        self.check_threats.start()

    async def on_ready(self):
        print(f'Logado como {self.user} (ID: {self.user.id})')
        print('Monitorando ameaças...')

    @tasks.loop(minutes=15) # Verifica a cada 15 minutos
    async def check_threats(self):
        # Tenta obter o canal
        channel = None
        if CHANNEL_ID:
            try:
                # Tenta pegar do cache primeiro
                channel = self.get_channel(int(CHANNEL_ID))
                # Se não estiver no cache, tenta buscar na API (garante que encontra)
                if not channel:
                    try:
                        channel = await self.fetch_channel(int(CHANNEL_ID))
                    except discord.NotFound:
                        print(f"ERRO CRÍTICO: Canal com ID {CHANNEL_ID} não encontrado na API.")
                    except discord.Forbidden:
                        print(f"ERRO CRÍTICO: Sem permissão para acessar o canal {CHANNEL_ID}.")
                    except Exception as e:
                        print(f"Erro ao buscar canal: {e}")
            except ValueError:
                print("Erro: DISCORD_CHANNEL_ID deve ser um número inteiro.")
        else:
            print("AVISO: DISCORD_CHANNEL_ID não configurado no arquivo .env")
        
        if not channel:
            print(f"Aviso: Não foi possível obter o objeto do canal (ID: {CHANNEL_ID}). O bot não poderá enviar mensagens.")
            # Continuamos para processar o feed e atualizar o cache, mas sem enviar
        else:
            print(f"Canal alvo identificado: {channel.name} (ID: {channel.id}) em {channel.guild.name}")

        print(f"Verificando feeds em: {datetime.now()}")

        for feed_url in FEEDS:
            try:
                feed = feedparser.parse(feed_url)
                if not feed.entries:
                    continue

                # Verifica as 10 entradas mais recentes de cada feed
                for i, entry in enumerate(feed.entries[:10]): 
                    # Usa o ID se existir, senão usa o link como identificador único
                    entry_id = entry.get('id', entry.get('link'))
                    
                    if not self.is_alert_sent(entry_id):
                        # Se for a primeira execução e o banco estava vazio (ou seja, novo uso), 
                        # podemos optar por não enviar TUDO, mas apenas o mais recente de cada, ou marcar como lido.
                        # Para garantir que não floode, vamos manter a lógica de enviar, mas com delay.
                        # O banco já garante que não repetiremos em restarts futuros.
                        
                        should_alert = True
                        
                        # Opcional: Se quiser evitar enviar 30 noticias na primeira vez que cria o banco,
                        # pode-se descomentar uma lógica de "skip old if first run". 
                        # Mas como o usuário pediu persistência, vamos assumir que se não está no banco, é novo.
                        
                        if should_alert:
                            if channel:
                                await self.send_alert(channel, entry, feed.feed.get('title', 'Fonte Desconhecida'))
                                self.mark_alert_sent(entry_id)
                                # Delay para evitar flood (130 segundos)
                                await asyncio.sleep(130)
                            else:
                                # Se não tiver canal, apenas marca como enviado para não travar
                                self.mark_alert_sent(entry_id) 
            except Exception as e:
                print(f"Erro ao ler feed {feed_url}: {e}")
        
        if self.first_run:
            self.first_run = False
            print("Inicialização completa. Monitoramento ativo.")
            if channel:
                 try:
                    await channel.send("🛡️ **Bot de Ameaças Iniciado!** Monitorando fontes públicas de segurança cibernética...")
                    print("Mensagem de boas-vindas enviada com sucesso.")
                 except Exception as e:
                    print(f"Não foi possível enviar mensagem de boas-vindas: {e}")
            else:
                print("Não foi possível enviar mensagem de boas-vindas: Canal não definido.")

    def extract_image_url(self, entry):
        # 1. Tenta pegar de media_content (comum em feeds de notícias)
        if 'media_content' in entry:
            for media in entry.media_content:
                if 'url' in media and ('image' in media.get('type', '') or media['url'].endswith(('.jpg', '.png', '.jpeg', '.gif'))):
                    return media['url']
        
        # 2. Tenta pegar de enclosures
        if 'enclosures' in entry:
            for enclosure in entry.enclosures:
                if 'image' in enclosure.get('type', '') or enclosure.get('href', '').endswith(('.jpg', '.png', '.jpeg', '.gif')):
                    return enclosure['href']
        
        # 3. Tenta pegar do link da imagem destaque (media_thumbnail)
        if 'media_thumbnail' in entry and len(entry.media_thumbnail) > 0:
             return entry.media_thumbnail[0]['url']

        # 4. Tenta encontrar tag <img> no summary ou content via Regex
        content = entry.get('summary', '') + entry.get('content', [{'value': ''}])[0].get('value', '')
        img_match = re.search(r'<img[^>]+src=["\'](.*?)["\']', content)
        if img_match:
            return img_match.group(1)
            
        return None

    async def send_alert(self, channel, entry, source):
        # Extrair o domínio do link para usar como FONTE
        from urllib.parse import urlparse
        domain = urlparse(entry.link).netloc.replace('www.', '')
        
        # Formatar a hora atual
        current_time = datetime.now().strftime("%H:%M")

        # Tentar extrair imagem
        image_url = self.extract_image_url(entry)
        
        # Se não encontrar imagem na notícia, usa a padrão
        if not image_url:
            image_url = DEFAULT_IMAGE_URL
            
        file_attachment = None

        if image_url:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(image_url) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            # Extrai extensão ou usa jpg como padrão
                            ext = 'jpg'
                            if '.' in image_url.split('/')[-1]:
                                ext = image_url.split('/')[-1].split('.')[-1].split('?')[0]
                                if len(ext) > 4: ext = 'jpg'
                            
                            file_attachment = discord.File(io.BytesIO(data), filename=f"image.{ext}")
            except Exception as e:
                print(f"Erro ao baixar imagem {image_url}: {e}")

        # Construir o Embed
        embed = discord.Embed(
            title=f"{entry.title}",
            url=entry.link,
            color=discord.Color.from_rgb(227, 16, 16), # Vermelho Threat
            timestamp=datetime.now()
        )
        
        embed.set_author(name="🚨 NOVO ALERTA CYBER THREAT 🚨")
        
        embed.add_field(name="🌐 FONTE", value=f"[{domain}]({entry.link})", inline=True)
        embed.add_field(name="🕒 HORA", value=current_time, inline=True)
        embed.add_field(name="🏷️ TAGS", value="#CyberSecurity #ThreatIntel", inline=False)
        
        embed.set_footer(text="🛡️ Desenvolvido por Deivid Araújo • Analista de Segurança (SOC) Jr | Ciberconscientizador")

        try:
            if file_attachment:
                # Anexa a imagem ao embed usando o nome do arquivo
                embed.set_image(url=f"attachment://{file_attachment.filename}")
                await channel.send(embed=embed, file=file_attachment)
            else:
                await channel.send(embed=embed)
            
            print(f"Alerta enviado: {entry.title}")
        except Exception as e:
            print(f"Erro ao enviar mensagem para o Discord: {e}")

    @check_threats.before_loop
    async def before_check_threats(self):
        await self.wait_until_ready()

if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("ERRO: DISCORD_TOKEN não encontrado. Configure o arquivo .env")
    else:
        intents = discord.Intents.default()
        # Intents necessários para enviar mensagens? Default geralmente cobre send_messages em canais que ele tem acesso
        client = ThreatBot(intents=intents)
        try:
            client.run(DISCORD_TOKEN)
        except Exception as e:
            print(f"Erro ao iniciar o bot: {e}")
