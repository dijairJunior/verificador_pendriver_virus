import os
import hashlib
import requests

def listar_unidades():
    """Lista as unidades conectadas ao sistema no Windows."""
    unidades = []
    for drive in range(65, 91):  # Leitura das letras de unidade de A a Z
        unidade = chr(drive) + ":\\"
        if os.path.exists(unidade):
            unidades.append(unidade)
    return unidades

def calcular_hash(arquivo):
    """Calcula o hash SHA256 de um arquivo."""
    sha256 = hashlib.sha256()
    try:
        with open(arquivo, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Erro ao calcular hash de {arquivo}: {e}")
        return None

def verificar_arquivos(diretorio):
    """Verifica arquivos suspeitos no diretório fornecido nas APIs."""
    suspicious_files = []
    for root, dirs, files in os.walk(diretorio):
        for file in files:
            caminho = os.path.join(root, file)
            hash_arquivo = calcular_hash(caminho)
            if hash_arquivo and verificar_na_api(hash_arquivo):
                suspicious_files.append(caminho)
    return suspicious_files

def verificar_na_api(hash_arquivo):
    """Verifica o hash do arquivo nas APIs de malware."""
    urls = [
        f"https://mb-api.abuse.ch/api/v1/?query=get_info&hash={hash_arquivo}",  # MalwareBazaar
        f"https://otx.alienvault.com/api/v1/indicators/file/{hash_arquivo}",  # AlienVault OTX
        f"https://www.hybrid-analysis.com/api/v2/search/hash?hash={hash_arquivo}"  # Hybrid Analysis
    ]
    
    for url in urls:
        response = requests.get(url)
        if response.status_code == 200:
            if "malware" in response.text or "suspicious" in response.text:
                return True
    return False

def salvar_relatorio(arquivos_suspeitos, caminho_pendrive):
    """Gera um arquivo TXT com informações sobre os arquivos e se são suspeitos."""
    nome_arquivo = "C:/Users/Usuario01/Desktop/Verificado/relatorio_pendrive.txt"
    with open(nome_arquivo, 'w', encoding='utf-8') as f:
        f.write(f"Relatório de Verificação de Pendrive - {caminho_pendrive}\n")
        f.write("=" * 50 + "\n")
        
        for root, dirs, files in os.walk(caminho_pendrive):
            for file in files:
                caminho = os.path.join(root, file)
                hash_arquivo = calcular_hash(caminho)
                f.write(f"\nArquivo: {caminho}\n")
                f.write(f"Hash SHA256: {hash_arquivo}\n")
                
                if hash_arquivo and verificar_na_api(hash_arquivo):
                    f.write("Status: Suspeito de conter malware\n")
                else:
                    f.write("Status: Limpo\n")
                f.write("-" * 50 + "\n")

    print(f"Relatório gerado: {nome_arquivo}")

def main():
    unidades = listar_unidades()
    if not unidades:
        print("Nenhum pendrive detectado.")
        return

    print("Pendrives detectados:")
    for idx, unidade in enumerate(unidades, 1):
        print(f"[{idx}] {unidade}")

    escolha = input("Selecione o número do pendrive para verificar: ")
    try:
        escolha = int(escolha)
        if 1 <= escolha <= len(unidades):
            arquivos_suspeitos = verificar_arquivos(unidades[escolha - 1])
            salvar_relatorio(arquivos_suspeitos, unidades[escolha - 1])
        else:
            print("Escolha inválida.")
    except ValueError:
        print("Entrada inválida.")

if __name__ == "__main__":
    main()
