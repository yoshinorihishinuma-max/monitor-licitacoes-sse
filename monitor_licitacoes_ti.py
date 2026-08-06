#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monitor de Licitacoes - SSE / SASE (aderencia Netskope) - PNCP
==============================================================

Consulta a API publica do Portal Nacional de Contratacoes Publicas (PNCP),
que desde a Lei 14.133/2021 consolida as contratacoes FEDERAIS, ESTADUAIS e
MUNICIPAIS, e filtra os PREGOES ELETRONICOS cujo objeto pode ser atendido por
solucoes do tipo SSE / SASE (Netskope): SASE, SSE, ZTNA, SWG, CASB, DLP em
nuvem, CSPM/SSPM, FWaaS, RBI, seguranca em nuvem, proxy/filtro web, Zero Trust.
Gera um digest em HTML + CSV e, opcionalmente, envia por e-mail.

Uso:
    python monitor_licitacoes_ti.py                 # dia util anterior
    python monitor_licitacoes_ti.py --dias 3        # ultimos 3 dias
    python monitor_licitacoes_ti.py --data 20260805 # uma data especifica
    python monitor_licitacoes_ti.py --uf SP,RJ,DF   # apenas algumas UFs
    python monitor_licitacoes_ti.py --enviar-email  # envia o digest por SMTP
    python monitor_licitacoes_ti.py --demo          # roda com dados de exemplo (sem rede)

Configuracao de e-mail via variaveis de ambiente (ou arquivo .env):
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM, EMAIL_TO

Licenca de uso livre. Sem garantias.
"""

import argparse
import csv
import datetime as dt
import json
import os
import re
import smtplib
import sys
import time
import unicodedata
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ---------------------------------------------------------------------------
# CONFIGURACAO
# ---------------------------------------------------------------------------

API_BASE = "https://pncp.gov.br/api/consulta/v1/contratacoes/publicacao"

# Modalidades a varrer (codigoModalidadeContratacao do PNCP).
# Configurado para monitorar APENAS Pregao Eletronico.
# Para incluir outras, adicione ao dicionario:
#   4 = Concorrencia Eletronica | 8 = Dispensa
#   9 = Inexigibilidade         | 12 = Credenciamento
MODALIDADES = {
    6: "Pregao Eletronico",
}

PAGE_SIZE = 50          # tamanho de pagina aceito com seguranca pela API
TIMEOUT = 45            # segundos por requisicao
RETRIES = 4             # tentativas por pagina
SLEEP_BETWEEN = 0.4     # pausa entre requisicoes (gentileza com o servidor)

# ---------------------------------------------------------------------------
# TAXONOMIA DE PALAVRAS-CHAVE  (foco: espaco de mercado SSE / SASE - Netskope)
# Todos os termos em minusculas e SEM acentos (o objeto e normalizado igual).
# ---------------------------------------------------------------------------

# ADERENTE: objeto claramente enderecavel por SSE/SASE (Netskope) -> prioridade
TERMOS_ADERENTE = [
    # Frameworks / siglas centrais
    "sase", "secure access service edge", "borda de servico de acesso seguro",
    "sse", "security service edge", "borda de servico de seguranca",
    "ztna", "zero trust network access", "acesso a rede zero trust",
    "zero trust", "confianca zero", "acesso privado seguro",
    # Secure Web Gateway / proxy / filtro web
    "swg", "secure web gateway", "gateway web seguro", "gateway de seguranca web",
    "proxy web", "filtro de conteudo web", "filtro web", "filtragem web",
    "web filtering", "seguranca de navegacao web", "protecao web",
    "controle de acesso a internet", "navegacao segura na web",
    # CASB / seguranca de SaaS e nuvem
    "casb", "cloud access security broker", "corretor de seguranca de acesso a nuvem",
    "seguranca em nuvem", "seguranca na nuvem", "cloud security",
    "seguranca de saas", "saas security", "seguranca de aplicacoes em nuvem",
    "shadow it", "descoberta de aplicacoes em nuvem", "descoberta de nuvem",
    "genai security", "seguranca de ia generativa",
    # DLP / protecao de dados em nuvem
    "dlp", "data loss prevention", "prevencao de vazamento de dados",
    "prevencao de perda de dados", "protecao de dados em nuvem",
    # Postura de seguranca
    "cspm", "cloud security posture", "postura de seguranca em nuvem",
    "sspm", "saas security posture",
    # FWaaS / RBI / inspecao
    "fwaas", "firewall as a service", "firewall como servico",
    "cloud firewall", "firewall em nuvem",
    "rbi", "remote browser isolation", "isolamento de navegador",
    "isolamento remoto de navegador",
    "inspecao ssl", "ssl inspection", "descriptografia ssl",
    "inspecao de trafego criptografado",
    # Acesso seguro / micro-seg
    "acesso remoto seguro", "acesso seguro a aplicacoes",
    "microssegmentacao", "micro-segmentacao",
]

# ADJACENTE: pode entrar em pregao de escopo maior onde a Netskope se aplica
TERMOS_ADJACENTE = [
    "firewall", "ngfw", "next generation firewall", "utm",
    "proxy", "servidor proxy",
    "vpn", "rede privada virtual", "acesso remoto",
    "sd-wan", "sdwan", "sd wan",
    "seguranca de rede", "seguranca perimetral", "protecao de perimetro",
    "seguranca de perimetro",
    "filtro de conteudo", "controle de navegacao", "navegacao segura",
    "mfa", "autenticacao multifator", "single sign", "sso",
    "gestao de identidade", "gestao de acesso", "iam", "pam",
    "protecao de dados", "lgpd", "privacidade de dados",
    "seguranca da informacao", "seguranca cibernetica", "ciberseguranca",
]

# Exclusoes: descarta falsos positivos quando NAO ha sinal aderente.
TERMOS_EXCLUSAO = [
    "seguranca do trabalho", "seguranca patrimonial", "seguranca privada",
    "vigilancia armada", "vigilancia desarmada", "vigilante", "vigias",
    "seguranca alimentar", "seguranca predial", "guarda patrimonial",
    "seguranca publica", "seguranca do paciente", "seguranca viaria",
    "brigada de incendio", "seguro", "seguros", "apolice",
]


# ---------------------------------------------------------------------------
# UTILIDADES
# ---------------------------------------------------------------------------

def normalizar(texto):
    """Minusculas, sem acentos, espacos colapsados (com espacos nas bordas)."""
    if not texto:
        return " "
    t = unicodedata.normalize("NFKD", texto)
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = t.lower()
    t = " ".join(t.split())
    return " " + t + " "


def carregar_dotenv(caminho=".env"):
    """Carrega variaveis simples KEY=VALUE de um arquivo .env, se existir."""
    if not os.path.exists(caminho):
        return
    with open(caminho, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            k, v = linha.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _compilar(termos):
    """Compila cada termo como regex com fronteira de palavra (evita casar
    'sse' dentro de 'acesso', ou 'nist' dentro de 'administrativas')."""
    pares = []
    for t in termos:
        t = t.strip()
        if not t:
            continue
        pares.append((t, re.compile(r"(?<!\w)" + re.escape(t) + r"(?!\w)")))
    return pares


_ADERENTE_RX = _compilar(TERMOS_ADERENTE)
_ADJACENTE_RX = _compilar(TERMOS_ADJACENTE)
_EXCL_RX = _compilar(TERMOS_EXCLUSAO)


def classificar(objeto):
    """
    Retorna ('ADERENTE'|'ADJACENTE'|None, [termos_encontrados]).
    Aderencia (fit Netskope) tem prioridade. Exclusao so vale quando NAO ha
    sinal aderente.
    """
    n = normalizar(objeto)

    ader_hits = [t for t, rx in _ADERENTE_RX if rx.search(n)]
    adj_hits = [t for t, rx in _ADJACENTE_RX if rx.search(n)]

    if not ader_hits and not adj_hits:
        return None, []

    if ader_hits:
        return "ADERENTE", sorted(set(ader_hits + adj_hits))

    # so sinal adjacente -> aplica exclusao
    if any(rx.search(n) for _, rx in _EXCL_RX):
        return None, []
    return "ADJACENTE", sorted(set(adj_hits))


def link_pncp(numero_controle):
    """
    Constroi o link publico do edital no PNCP a partir do numeroControlePNCP.
    Formato: '{cnpj}-1-{sequencial}/{ano}'
    URL:     https://pncp.gov.br/app/editais/{cnpj}/{ano}/{sequencial}
    """
    try:
        esquerda, ano = numero_controle.split("/")
        partes = esquerda.split("-")
        cnpj = partes[0]
        sequencial = str(int(partes[-1]))  # remove zeros a esquerda
        return f"https://pncp.gov.br/app/editais/{cnpj}/{ano}/{sequencial}"
    except Exception:
        return "https://pncp.gov.br/app/editais"


# ---------------------------------------------------------------------------
# ACESSO A API
# ---------------------------------------------------------------------------

def buscar_pagina(data_ini, data_fim, modalidade, pagina, uf=None):
    params = {
        "dataInicial": data_ini,
        "dataFinal": data_fim,
        "codigoModalidadeContratacao": modalidade,
        "pagina": pagina,
        "tamanhoPagina": PAGE_SIZE,
    }
    if uf:
        params["uf"] = uf
    url = API_BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (monitor-licitacoes-sse)",
            "Accept": "application/json",
        },
    )
    ultimo_erro = None
    for tentativa in range(1, RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                if r.status == 204:
                    return {"data": [], "totalPaginas": 0}
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa
            ultimo_erro = e
            time.sleep(1.5 * tentativa)
    print(f"  [aviso] falha modalidade {modalidade} pagina {pagina}: {ultimo_erro}",
          file=sys.stderr)
    return {"data": [], "totalPaginas": 0}


def _montar_registro(it, categoria, termos, modalidade_nome):
    org = it.get("orgaoEntidade") or {}
    und = it.get("unidadeOrgao") or {}
    chave = it.get("numeroControlePNCP")
    return {
        "categoria": categoria,
        "termos": ", ".join(termos),
        "objeto": (it.get("objetoCompra") or "").strip(),
        "orgao": org.get("razaoSocial"),
        "esfera": {1: "Federal", 2: "Estadual", 3: "Municipal"}.get(
            org.get("esferaId"), org.get("esferaId")),
        "uf": und.get("ufSigla"),
        "municipio": und.get("municipioNome"),
        "unidade": und.get("nomeUnidade"),
        "modalidade": it.get("modalidadeNome") or modalidade_nome,
        "situacao": it.get("situacaoCompraNome"),
        "valor_estimado": it.get("valorTotalEstimado"),
        "publicacao": (it.get("dataPublicacaoPncp") or "")[:10],
        "abertura": (it.get("dataAberturaProposta") or "")[:16].replace("T", " "),
        "encerramento": (it.get("dataEncerramentoProposta") or "")[:16].replace("T", " "),
        "numero_controle": chave,
        "link": link_pncp(chave or ""),
        "link_origem": it.get("linkSistemaOrigem") or "",
    }


def _ordenar(itens):
    prioridade = {"ADERENTE": 0, "ADJACENTE": 1}
    itens.sort(key=lambda x: (
        prioridade.get(x["categoria"], 9),
        -(x["valor_estimado"] or 0),
        x["uf"] or "",
    ))
    return itens


def coletar(data_ini, data_fim, ufs=None):
    """Varre todas as modalidades/paginas e retorna registros filtrados."""
    ufs_lista = ufs if ufs else [None]
    encontrados = {}  # chave: numeroControlePNCP -> registro

    for uf in ufs_lista:
        for cod, nome in MODALIDADES.items():
            pagina = 1
            total_paginas = 1
            while pagina <= total_paginas:
                resp = buscar_pagina(data_ini, data_fim, cod, pagina, uf)
                total_paginas = resp.get("totalPaginas") or 0
                for it in (resp.get("data") or []):
                    categoria, termos = classificar(it.get("objetoCompra"))
                    if not categoria:
                        continue
                    chave = it.get("numeroControlePNCP")
                    if chave in encontrados:
                        continue
                    encontrados[chave] = _montar_registro(it, categoria, termos, nome)
                if total_paginas == 0:
                    break
                pagina += 1
                time.sleep(SLEEP_BETWEEN)

    return _ordenar(list(encontrados.values()))


# ---------------------------------------------------------------------------
# SAIDA (HTML / CSV)
# ---------------------------------------------------------------------------

def fmt_moeda(v):
    if v is None:
        return "-"
    try:
        return "R$ " + f"{float(v):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return str(v)


def gerar_html(itens, periodo):
    ader = [i for i in itens if i["categoria"] == "ADERENTE"]
    adj = [i for i in itens if i["categoria"] == "ADJACENTE"]

    def linha(i):
        aderente = i["categoria"] == "ADERENTE"
        badge_cor = "#047857" if aderente else "#b45309"
        badge_txt = "Aderente SSE/SASE" if aderente else "Adjacente"
        return f"""
      <tr>
        <td><span style="background:{badge_cor};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;white-space:nowrap;">{badge_txt}</span></td>
        <td style="max-width:420px;">
          <a href="{i['link']}" style="color:#0f172a;font-weight:600;text-decoration:none;">{(i['objeto'] or '')[:220]}</a>
          <div style="color:#64748b;font-size:11px;margin-top:3px;">termos: {i['termos']}</div>
        </td>
        <td>{i['orgao'] or '-'}<div style="color:#64748b;font-size:11px;">{i['esfera'] or ''}</div></td>
        <td style="text-align:center;">{i['uf'] or '-'}<div style="color:#64748b;font-size:11px;">{(i['municipio'] or '')[:24]}</div></td>
        <td style="text-align:right;white-space:nowrap;">{fmt_moeda(i['valor_estimado'])}</td>
        <td style="white-space:nowrap;">{i['encerramento'] or '-'}</td>
        <td><a href="{i['link']}" style="color:#2563eb;">abrir</a></td>
      </tr>"""

    def tabela(lista):
        if not lista:
            return '<p style="color:#64748b;">Nenhum edital nesta faixa no periodo.</p>'
        cabecalho = """
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <thead>
          <tr style="background:#f1f5f9;text-align:left;">
            <th style="padding:8px;">Faixa</th><th style="padding:8px;">Objeto</th>
            <th style="padding:8px;">Orgao</th><th style="padding:8px;">UF</th>
            <th style="padding:8px;">Valor est.</th>
            <th style="padding:8px;">Encerramento</th><th style="padding:8px;">Link</th>
          </tr>
        </thead><tbody>"""
        return cabecalho + "".join(linha(i) for i in lista) + "</tbody></table>"

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Monitor de Licitacoes - SSE / SASE</title></head>
<body style="font-family:Arial,Helvetica,sans-serif;color:#0f172a;background:#ffffff;margin:0;padding:24px;">
  <div style="max-width:1000px;margin:0 auto;">
    <h1 style="font-size:20px;margin:0 0 4px;">Monitor de Licitacoes &mdash; SSE / SASE (aderencia Netskope)</h1>
    <p style="color:#475569;margin:0 0 16px;">Fonte: PNCP &middot; Pregao Eletronico &middot; federal, estadual e municipal &middot; Periodo: <b>{periodo}</b></p>
    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
      <div style="background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;padding:12px 16px;">
        <div style="font-size:24px;font-weight:700;color:#047857;">{len(ader)}</div>
        <div style="font-size:12px;color:#065f46;">Aderente SSE/SASE</div></div>
      <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px 16px;">
        <div style="font-size:24px;font-weight:700;color:#b45309;">{len(adj)}</div>
        <div style="font-size:12px;color:#92400e;">Adjacente / possivel</div></div>
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;">
        <div style="font-size:24px;font-weight:700;">{len(itens)}</div>
        <div style="font-size:12px;color:#475569;">Total de editais</div></div>
    </div>
    <h2 style="font-size:16px;color:#047857;">Aderente SSE/SASE (fit Netskope)</h2>
    {tabela(ader)}
    <h2 style="font-size:16px;color:#b45309;margin-top:28px;">Adjacente / possivel</h2>
    {tabela(adj)}
    <p style="color:#94a3b8;font-size:11px;margin-top:28px;">
      Gerado automaticamente. Confira sempre o edital completo no PNCP antes de tomar decisoes.
      Filtro por palavras-chave pode gerar falsos positivos/negativos &mdash; ajuste a taxonomia no script.
    </p>
  </div>
</body></html>"""


def salvar_csv(itens, caminho):
    campos = ["categoria", "termos", "objeto", "orgao", "esfera", "uf", "municipio",
              "unidade", "modalidade", "situacao", "valor_estimado", "publicacao",
              "abertura", "encerramento", "numero_controle", "link", "link_origem"]
    with open(caminho, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for i in itens:
            w.writerow({k: i.get(k, "") for k in campos})


# ---------------------------------------------------------------------------
# E-MAIL
# ---------------------------------------------------------------------------

def enviar_email(html, periodo, n_ader, n_total, anexo_csv=None):
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    senha = os.environ.get("SMTP_PASS")
    de = os.environ.get("EMAIL_FROM", user)
    para = os.environ.get("EMAIL_TO")

    if not (user and senha and para):
        print("[erro] defina SMTP_USER, SMTP_PASS e EMAIL_TO para enviar e-mail.",
              file=sys.stderr)
        return False

    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"[Licitacoes SSE/SASE] {n_ader} aderentes / {n_total} total - {periodo}"
    msg["From"] = de
    msg["To"] = para
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText("Seu leitor nao suporta HTML. Veja o anexo/relatorio.", "plain", "utf-8"))
    alt.attach(MIMEText(html, "html", "utf-8"))
    msg.attach(alt)

    if anexo_csv and os.path.exists(anexo_csv):
        from email.mime.base import MIMEBase
        from email import encoders
        with open(anexo_csv, "rb") as f:
            part = MIMEBase("text", "csv")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment",
                        filename=os.path.basename(anexo_csv))
        msg.attach(part)

    destinatarios = [x.strip() for x in para.split(",") if x.strip()]
    with smtplib.SMTP(host, port, timeout=TIMEOUT) as s:
        s.starttls()
        s.login(user, senha)
        s.sendmail(de, destinatarios, msg.as_string())
    print(f"[ok] e-mail enviado para {para}")
    return True


# ---------------------------------------------------------------------------
# DADOS DE DEMONSTRACAO (modo --demo, sem rede)
# ---------------------------------------------------------------------------

DEMO = [
    {"objetoCompra": "Contratacao de solucao SASE com SWG (secure web gateway), CASB e ZTNA para acesso seguro dos servidores da Secretaria",
     "numeroControlePNCP": "12345678000199-1-000042/2026",
     "orgaoEntidade": {"razaoSocial": "SECRETARIA DE ESTADO DA FAZENDA", "esferaId": 2},
     "unidadeOrgao": {"ufSigla": "SP", "municipioNome": "Sao Paulo", "nomeUnidade": "SEFAZ-SP"},
     "modalidadeNome": "Pregao - Eletronico", "situacaoCompraNome": "Divulgada no PNCP",
     "valorTotalEstimado": 2450000.00, "dataPublicacaoPncp": "2026-08-05T00:00:03",
     "dataAberturaProposta": "2026-08-06T09:00:00", "dataEncerramentoProposta": "2026-08-20T09:00:00",
     "linkSistemaOrigem": ""},
    {"objetoCompra": "Solucao de seguranca em nuvem com DLP (data loss prevention) e CASB para protecao de dados em aplicacoes SaaS",
     "numeroControlePNCP": "00394460000141-1-000318/2026",
     "orgaoEntidade": {"razaoSocial": "MINISTERIO DA GESTAO E DA INOVACAO", "esferaId": 1},
     "unidadeOrgao": {"ufSigla": "DF", "municipioNome": "Brasilia", "nomeUnidade": "Coordenacao de TI"},
     "modalidadeNome": "Pregao - Eletronico", "situacaoCompraNome": "Divulgada no PNCP",
     "valorTotalEstimado": 8900000.00, "dataPublicacaoPncp": "2026-08-05T00:00:10",
     "dataAberturaProposta": "2026-08-07T14:00:00", "dataEncerramentoProposta": "2026-08-25T14:00:00",
     "linkSistemaOrigem": "https://www.gov.br/compras"},
    {"objetoCompra": "Aquisicao de solucao de VPN e firewall de proxima geracao (NGFW) para a rede corporativa do orgao",
     "numeroControlePNCP": "10585138000155-1-000091/2026",
     "orgaoEntidade": {"razaoSocial": "TRIBUNAL DE JUSTICA DO ESTADO DO RIO DE JANEIRO", "esferaId": 2},
     "unidadeOrgao": {"ufSigla": "RJ", "municipioNome": "Rio de Janeiro", "nomeUnidade": "DGTEC"},
     "modalidadeNome": "Pregao - Eletronico", "situacaoCompraNome": "Divulgada no PNCP",
     "valorTotalEstimado": 640000.00, "dataPublicacaoPncp": "2026-08-05T00:01:00",
     "dataAberturaProposta": "", "dataEncerramentoProposta": "2026-08-12T18:00:00",
     "linkSistemaOrigem": ""},
    {"objetoCompra": "Aquisicao de computadores desktop e notebooks para as unidades administrativas",
     "numeroControlePNCP": "01612441000107-1-000115/2026",
     "orgaoEntidade": {"razaoSocial": "MUNICIPIO DE BELA VISTA DO CAROBA", "esferaId": 3},
     "unidadeOrgao": {"ufSigla": "PR", "municipioNome": "Bela Vista da Caroba", "nomeUnidade": "Prefeitura"},
     "modalidadeNome": "Pregao - Eletronico", "situacaoCompraNome": "Divulgada no PNCP",
     "valorTotalEstimado": 185000.00, "dataPublicacaoPncp": "2026-08-05T00:00:03",
     "dataAberturaProposta": "2026-08-06T08:00:00", "dataEncerramentoProposta": "2026-08-18T08:00:00",
     "linkSistemaOrigem": "https://pregaobanrisul.com.br"},
    {"objetoCompra": "Contratacao de empresa de vigilancia armada e seguranca patrimonial (NAO deve aparecer)",
     "numeroControlePNCP": "99999999000199-1-000001/2026",
     "orgaoEntidade": {"razaoSocial": "PREFEITURA EXEMPLO", "esferaId": 3},
     "unidadeOrgao": {"ufSigla": "MG", "municipioNome": "Exemplo", "nomeUnidade": "Adm"},
     "modalidadeNome": "Pregao - Eletronico", "situacaoCompraNome": "Divulgada no PNCP",
     "valorTotalEstimado": 500000.00, "dataPublicacaoPncp": "2026-08-05T00:00:03",
     "dataAberturaProposta": "", "dataEncerramentoProposta": "2026-08-15T08:00:00",
     "linkSistemaOrigem": ""},
]


def coletar_demo():
    encontrados = []
    for it in DEMO:
        categoria, termos = classificar(it.get("objetoCompra"))
        if not categoria:
            continue
        encontrados.append(_montar_registro(it, categoria, termos, it.get("modalidadeNome")))
    return _ordenar(encontrados)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def dia_util_anterior(hoje):
    d = hoje - dt.timedelta(days=1)
    while d.weekday() >= 5:  # 5=sab, 6=dom
        d -= dt.timedelta(days=1)
    return d


def main():
    carregar_dotenv()
    ap = argparse.ArgumentParser(description="Monitor de licitacoes SSE/SASE (Netskope) - PNCP")
    ap.add_argument("--dias", type=int, default=1, help="quantos dias para tras (default 1 = dia util anterior)")
    ap.add_argument("--data", type=str, help="data especifica AAAAMMDD (ignora --dias)")
    ap.add_argument("--uf", type=str, help="lista de UFs separadas por virgula (ex: SP,RJ,DF). Vazio = Brasil todo")
    ap.add_argument("--enviar-email", action="store_true", help="envia o digest por e-mail (SMTP)")
    ap.add_argument("--saida", type=str, default=".", help="diretorio de saida")
    ap.add_argument("--demo", action="store_true", help="roda com dados de exemplo (sem rede)")
    args = ap.parse_args()

    hoje = dt.date.today()

    if args.demo:
        itens = coletar_demo()
        periodo = "DEMONSTRACAO (dados de exemplo)"
        rotulo = "demo"
    else:
        if args.data:
            data_ini = data_fim = args.data
            periodo = f"{args.data[6:8]}/{args.data[4:6]}/{args.data[0:4]}"
            rotulo = args.data
        else:
            alvo = dia_util_anterior(hoje) if args.dias == 1 else hoje - dt.timedelta(days=args.dias)
            data_ini = alvo.strftime("%Y%m%d")
            data_fim = hoje.strftime("%Y%m%d")
            periodo = f"{alvo.strftime('%d/%m/%Y')} a {hoje.strftime('%d/%m/%Y')}"
            rotulo = f"{data_ini}_{data_fim}"
        ufs = [u.strip().upper() for u in args.uf.split(",")] if args.uf else None
        print(f"Consultando PNCP | periodo {periodo} | UFs: {ufs or 'BRASIL'} | "
              f"modalidades: {list(MODALIDADES.values())}")
        itens = coletar(data_ini, data_fim, ufs)

    n_ader = sum(1 for i in itens if i["categoria"] == "ADERENTE")
    n_total = len(itens)
    print(f"Encontrados: {n_total} editais ({n_ader} aderentes a SSE/SASE)")

    os.makedirs(args.saida, exist_ok=True)
    html = gerar_html(itens, periodo)
    html_path = os.path.join(args.saida, f"licitacoes_sse_{rotulo}.html")
    csv_path = os.path.join(args.saida, f"licitacoes_sse_{rotulo}.csv")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    salvar_csv(itens, csv_path)
    print(f"Relatorio HTML: {html_path}")
    print(f"Planilha CSV:   {csv_path}")

    if args.enviar_email:
        enviar_email(html, periodo, n_ader, n_total, anexo_csv=csv_path)


if __name__ == "__main__":
    main()
