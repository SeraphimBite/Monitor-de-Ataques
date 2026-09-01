# Monitor-de-Ataques

Uma implementação em C++ de um sistema de monitoramento de tráfego capaz de analisar pacotes de rede e identificar comportamentos potencialmente maliciosos.

O projeto utiliza a biblioteca `libpcap` para acessar o tráfego de rede e oferece dois modos de operação: captura de pacotes diretamente de uma interface de rede e análise de arquivos `.pcap` previamente capturados.

## O problema

Em uma rede, diferentes tipos de ataques podem produzir padrões observáveis no tráfego. Alguns possuem características conhecidas que podem ser reconhecidas por regras específicas, enquanto outros podem ser identificados por comportamentos que fogem de determinados padrões esperados.

Este projeto aborda essas duas situações utilizando mecanismos independentes de detecção.

```text
                         Trafego de rede
                               |
                               v
                       Captura de pacotes
                               |
                               v
                         Processamento
                               |
                  +------------+------------+
                  |                         |
                  v                         v
             Assinaturas              Anomalias
                  |                         |
                  +------------+------------+
                               |
                               v
                         Resultado da analise
                               |
                               v
                            Registro
```

## Como a análise funciona

Cada pacote capturado passa pelo processamento do sistema e pode ser avaliado por dois mecanismos.

### Analise por assinaturas

O primeiro mecanismo procura padrões previamente conhecidos.

As assinaturas são mantidas em um arquivo de configuração, permitindo que novos padrões sejam adicionados sem modificar diretamente a lógica principal da aplicação.

```text
config/signatures.txt
```

Quando um pacote corresponde a uma assinatura configurada, o sistema pode gerar um alerta.

Essa abordagem é adequada para comportamentos que já possuem características conhecidas.

### Analise de anomalias

O segundo mecanismo procura comportamentos considerados fora do padrão.

Em vez de depender exclusivamente de uma assinatura específica, a aplicação utiliza limites de tráfego para identificar situações que podem indicar atividade suspeita.

Essa abordagem complementa a análise por assinaturas, permitindo observar o comportamento geral da rede.

## Duas formas de utilizar o sistema

O projeto pode trabalhar tanto com tráfego atual quanto com capturas realizadas anteriormente.

### Monitoramento em tempo real

A aplicação pode utilizar `libpcap` para capturar os pacotes diretamente de uma interface de rede.

```bash
sudo ./nids --live eth0
```

Nesse modo, o sistema permanece observando o tráfego recebido pela interface e executa a análise conforme os pacotes são capturados.

### Analise de uma captura existente

Também é possível utilizar um arquivo PCAP como fonte de dados:

```bash
./nids --pcap sample.pcap
```

Esse modo é útil para testar o detector com tráfego previamente registrado, permitindo repetir uma mesma análise sem depender de uma captura em tempo real.

## Registro dos resultados

Os eventos identificados pelo sistema são armazenados em arquivos de log.

```text
logs/
├── alerts.log
└── traffic.log
```

O `alerts.log` concentra os eventos considerados relevantes para segurança, enquanto `traffic.log` mantém informações relacionadas ao tráfego analisado.

## Organização do código

O projeto separa a captura, o processamento e os mecanismos de detecção em componentes diferentes.

```text
src/
|
+-- main.cpp
|      Inicializacao da aplicacao
|
+-- live_sniffer.cpp
|      Captura de trafego em tempo real
|
+-- pcap_reader.cpp
|      Leitura de arquivos PCAP
|
+-- processor.cpp
|      Processamento dos pacotes
|
+-- signature_detection.cpp
|      Analise baseada em assinaturas
|
+-- anomaly_detection.cpp
|      Analise baseada em anomalias
|
+-- utils.cpp
       Funcoes auxiliares
```

As interfaces correspondentes ficam organizadas no diretório `include/`, enquanto as configurações das assinaturas ficam em `config/`.

## Tecnologias

| Tecnologia   | Utilizacao                            |
| ------------ | ------------------------------------- |
| C++          | Implementação do sistema              |
| C++17        | Padrão utilizado na compilação        |
| libpcap      | Captura e leitura de pacotes          |
| PCAP         | Fonte de tráfego para análise offline |
| Linux / WSL2 | Ambiente de execução                  |

O projeto foi desenvolvido e testado em WSL2 com Ubuntu e `libpcap`.

## Compilacao

Em sistemas baseados em Debian ou Ubuntu, instale as dependências:

```bash
sudo apt update
sudo apt install g++ make libpcap-dev
```

Depois compile o projeto:

```bash
g++ -std=c++17 src/*.cpp -I include -lpcap -o nids
```

O executável `nids` será criado no diretório do projeto.

## Exemplo de fluxo

Uma utilização típica pode ser representada assim:

```text
1. Interface de rede
        |
        v
2. Captura de pacotes
        |
        v
3. Processamento
        |
        +------> Verificacao de assinaturas
        |
        +------> Verificacao de anomalias
        |
        v
4. Identificacao de evento
        |
        v
5. Registro no log
```

O mesmo fluxo pode ser aplicado a uma captura PCAP, substituindo a interface de rede pelo arquivo de entrada.

## O que este projeto demonstra

O projeto reúne conceitos de diferentes áreas de desenvolvimento de sistemas:

* Programação em C++
* Redes de computadores
* Captura e processamento de pacotes
* Análise de tráfego
* Detecção de intrusões
* Engenharia de software
* Segurança da informação
* Processamento de dados em baixo nível

Por utilizar `libpcap` diretamente e separar os componentes responsáveis pela captura, processamento e detecção, o projeto também serve como exemplo prático de desenvolvimento de uma ferramenta de segurança de rede em C++.

## Possibilidades de evolucao

A arquitetura atual pode servir como base para funcionalidades adicionais, como:

* Suporte a novos tipos de assinaturas
* Regras de detecção mais complexas
* Classificação de diferentes tipos de ataques
* Novos métodos de análise de anomalias
* Exportação dos alertas em JSON
* Armazenamento dos eventos em banco de dados
* Interface para visualização do tráfego
* Estatísticas de rede em tempo real
* Integração com sistemas de monitoramento
* Utilização de Machine Learning para classificação de tráfego

## Consideracoes de seguranca

A captura de pacotes deve ser realizada somente em redes e dispositivos para os quais exista autorização de monitoramento.

O sistema deve ser considerado uma ferramenta de estudo e análise, não um substituto para soluções profissionais de segurança de rede.

## Objetivo

O objetivo do projeto é implementar uma base funcional para detecção de intrusões em redes utilizando C++ e `libpcap`, combinando análise baseada em padrões conhecidos com identificação de comportamentos anormais.

A combinação dessas abordagens permite explorar diferentes técnicas de detecção dentro de uma única aplicação, mantendo a implementação organizada em componentes independentes.
