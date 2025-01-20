# verificador_pendriver_virus
Este script Python automatiza a verificação de arquivos em pendrives usando o serviço VirusTotal. Ele calcula o hash SHA256 de cada arquivo e consulta a API do VirusTotal para verificar se há detecções de malware, gerando um relatório TXT com data.

## Recapitulação das Funcionalidades e Melhorias

Como o código parece estar funcionando como esperado, gostaria de recapitular as principais funcionalidades e melhorias que implementamos ao longo da nossa conversa:

*   **Listagem de unidades:** O código lista corretamente as unidades de disco removíveis conectadas ao sistema.
*   **Cálculo de hash \*\*SHA256\*\***: Calcula o hash \*\*SHA256\*\* dos arquivos de forma eficiente e tratando possíveis erros de leitura de arquivos.
*   **Consulta à API do \*\*VirusTotal\*\***: Consulta a API do \*\*VirusTotal\*\* usando o hash \*\*SHA256\*\*, verificando se o arquivo já foi analisado e obtendo informações sobre detecções.
*   **Geração de relatório:** Gera um relatório em formato \*\*TXT\*\* com informações sobre os arquivos verificados, incluindo:
    *   Hash \*\*SHA256\*\*
    *   Status da verificação do \*\*VirusTotal\*\*
    *   Informações sobre detecções (maliciosas e suspeitas)
*   **Nome do arquivo do relatório com data e hora:** Inclui a data e hora da geração no nome do arquivo do relatório para evitar sobrescritas e manter um histórico.
*   **Tratamento robusto de erros:** Implementamos tratamento de erros em várias partes do código, incluindo:
    *   Erros de leitura de arquivos
    *   Erros de requisição à API do \*\*VirusTotal\*\* (incluindo tratamento específico para erros \*\*401\*\* - Não Autorizado, \*\*404\*\* - Não Encontrado e \*\*429\*\* - Muitas Requisições)
    *   Erros de acesso ao sistema de arquivos para criar o relatório
    *   Outros erros inesperados
*   **Melhorias de legibilidade e organização:** Simplificamos a lógica de processamento da resposta do \*\*VirusTotal\*\* e melhoramos a formatação do relatório para torná-lo mais legível.
