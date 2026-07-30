# NaturaGuard — app Android real (não só especificação)

Este é o código-fonte real da app Android construída a partir da
especificação do `mobile-android-agent` (`.claude/agents/mobile-android-agent.md`).
Pacote: `com.algoritmonatural.naturaguard`.

## Aviso honesto sobre o estado disto

Este código foi escrito por um agente Claude Code **sem acesso ao Android
SDK** — só havia Gradle e Java disponíveis no ambiente onde foi escrito.
Isto significa:

- **Nunca foi compilado.** Não há garantia de que compila sem erros à
  primeira. É código real e estruturalmente correto ao melhor do meu
  conhecimento, mas não foi validado por um compilador Kotlin/Android real.
- **Nunca correu num dispositivo ou emulador.** As quatro funcionalidades
  (monitor de rede, auditoria de uso, modo dispositivo dedicado, deteção
  de root) não foram testadas em runtime.
- Antes de instalar isto no seu telemóvel a sério, abra o projeto no
  Android Studio, resolva os erros de compilação que aparecerem (é normal
  haver alguns numa primeira geração destas), e teste cada funcionalidade
  isoladamente.

Isto é um ponto de partida real e completo — não um protótipo vazio — mas
precisa da vossa passagem pelo Android Studio antes de ir para o telemóvel.

## O que está implementado

| Módulo | Ficheiro | O que faz |
| --- | --- | --- |
| Monitor de rede | `vpnmonitor/NetworkMonitorService.kt` | `VpnService` local, sem root. Lê pacotes IPv4 do TUN, regista ligações a portas de gestão suspeitas (23/3389), devolve todos os pacotes inalterados (não bloqueia nada). |
| Auditoria de uso | `usageaudit/UsageAuditManager.kt` | Lê `UsageStatsManager` das últimas 24h, só depois de confirmar que `PACKAGE_USAGE_STATS` foi concedido manualmente pelo utilizador. |
| Modo dispositivo dedicado | `deviceowner/DeviceOwnerReceiver.kt` | `DeviceAdminReceiver` para aprovisionamento Device Owner. Regista eventos de ativação/desativação. |
| Deteção de root | `rootdetection/RootDetector.kt` | Heurística de ficheiros/binário `su` conhecidos. É um sinal, não uma garantia — a mesma honestidade que o `netguard/README.md` já assume para a sua própria lista de MAC autorizados. |
| Eventos partilhados | `shared/EventLogger.kt` | Grava `events.jsonl` no armazenamento privado da app, com o mesmo formato de severidade (`critico`/`aviso`/`info`) do `netguard/netguard.py`, para que um relatório futuro possa juntar os dois. |
| Portas sensíveis alargadas | `vpnmonitor/NetworkMonitorService.kt` | Passou de vigiar só 23/3389 para uma lista de 11 portas (SSH, SMB, bases de dados, VNC, TR-069, etc.) — regista uma vez por sessão, não por pacote. |
| Segurança do Wi-Fi | `wifisecurity/WifiSecurityChecker.kt` | Lê as capacidades anunciadas pelo ponto de acesso a que está ligado (aberto/WEP/WPA) a partir do último scan — a mesma informação que o seletor de Wi-Fi do Android já mostra. |
| Deteção de mudança de gateway (ARP) | `arpmonitor/GatewayMonitor.kt` | Equivalente ao `gateway_mac_changed` do `netguard/netguard.py`: compara o MAC do router com o último conhecido. Em Android 10+ sem root, `/proc/net/arp` pode estar ilegível — nesse caso devolve `DEGRADED`, nunca finge que verificou. |
| Relatório na app | `report/ReportActivity.kt` | Lê `events.jsonl` e mostra os eventos de aviso/crítico mais recentes primeiro — o "registo dos IPs/portas sinalizados" dentro da própria app. |
| VPN cifrada (WireGuard) | `wireguard/` | Cliente oficial WireGuard (`com.wireguard.android:tunnel`) — **não é criptografia escrita à mão**. Ver aviso abaixo. |

## Sobre o "VPN hyper segura" (WireGuard)

Isto **não é o mesmo tipo de VPN** que o monitor de rede. O monitor
(`vpnmonitor/`) intercepta pacotes localmente para os inspecionar, mas o
tráfego continua a sair de casa sem cifra extra. O módulo `wireguard/`
cifra o tráfego até um servidor fora da rede doméstica — é isto que
protege contra alguém com acesso ao router (administrador mal-intencionado,
ISP, ou um atacante que já esteja na LAN).

**Isto precisa de um servidor WireGuard que o utilizador já tenha** — a
app não cria um do nada. Duas opções:

1. **Servidor próprio**: um VPS barato (DigitalOcean, Hetzner, etc.) com
   WireGuard instalado — dá controlo total, sem confiar em terceiros.
2. **Fornecedor comercial**: qualquer VPN que exporte configuração
   WireGuard (ficheiro `.conf`).

Em qualquer um dos casos: abra `TunnelConfigActivity` (botão "Configurar
VPN segura (WireGuard)" no ecrã principal), cole o conteúdo do `.conf`, e
ligue. A configuração fica guardada com `EncryptedSharedPreferences`
(`wireguard/SecureConfigStore.kt`) porque contém uma chave privada — nunca
em texto simples.

## O que NÃO está implementado (por regra rígida do agente, não por falta de tempo)

- Nenhuma leitura de notificações de outra app (`NotificationListenerService`).
- Nenhum uso de `AccessibilityService` para vigilância.

Estas duas ficam de fora mesmo com o modo Device Owner ativo, porque o
`mobile-android-agent` exige também consentimento demonstrável de quem usa
o dispositivo — algo que não pode ser verificado só por código. Implementá-las
exigiria uma decisão humana explícita, caso a caso.

## Como compilar

1. Instale o [Android Studio](https://developer.android.com/studio).
2. Abra a pasta `naturaguard-android/` como projeto.
3. Deixe o Android Studio sincronizar o Gradle (vai pedir para instalar o
   SDK 34 e o Build Tools correspondentes, se ainda não os tiver).
4. **Build → Make Project** — corrija os erros que aparecerem primeiro.
5. Ligue o telemóvel por USB com Depuração USB ativa, ou use um emulador.
6. **Run → Run 'app'**.

## Testar cada funcionalidade

- **Monitor de rede**: botão "Iniciar monitor de rede" pede permissão de
  VPN do Android — é normal aparecer o ícone de chave/VPN na barra de
  estado enquanto está ativo.
- **Deteção de root**: só é significativo num telemóvel com root real; num
  telemóvel normal deve devolver "sem indícios".
- **Auditoria de uso**: primeira vez vai pedir para ir a Definições →
  Acesso a dados de utilização e ativar manualmente para o NaturaGuard.
- **Modo dispositivo dedicado**: só pode ser aprovisionado num dispositivo
  em reset de fábrica, via QR/NFC ou `adb shell dpm set-device-owner
  com.algoritmonatural.naturaguard/.deviceowner.DeviceOwnerReceiver` — não
  se torna Device Owner só por abrir a app.
- **Segurança do Wi-Fi**: primeira vez vai pedir permissão de localização
  (ou "dispositivos próximos" em Android 13+) — é exigência do próprio
  Android para ler resultados de scan de Wi-Fi, não algo que a app peça
  por gosto.
- **Gateway/ARP**: no desktop/Termux (netguard) isto funciona sempre; no
  telemóvel só funciona em Android <10 ou com root — nos outros casos vai
  mostrar "não foi possível ler a tabela ARP", o que é esperado, não um bug.
- **WireGuard**: sem um `.conf` válido colado primeiro, o botão "Ligar"
  mostra um erro claro em vez de falhar silenciosamente.

## Relatório de conformidade

Antes de submeter à Play Store, isto precisa de passar pelo
`security-review-agent` (justificação de permissões sensíveis) e o texto
resultante deve ir para a declaração de utilização de permissões da Play
Console — ver `.claude/agents/mobile-android-agent.md`, secção "Output
esperado".
