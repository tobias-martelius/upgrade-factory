# Upgrade Lab — Rust + native sandbox

Målet är ett självbärande verktyg för SBOM, sårbarhetsskanning och gemensamt
godkända uppgraderingar av Java-repon. **Inget Docker-/Compose-beroende i den nya
Rust-versionen.**

## Status

Rust-versionen har ett verkligt, testat **sandboxlager för macOS** och en första
**verktygshanterare för JDK, Maven och Trivy**:

- Seatbelt via den fasta systemsökvägen `/usr/bin/sandbox-exec`.
- Deny-by-default med explicit filåtkomst och stängt nätverk som standard.
- Barnprocesser ärver samma sandbox.
- Tom ärvd miljö, privat tillfällig HOME, TMPDIR och arbetskatalog.
- Tidsgräns och avslutning av jobbets processgrupp.
- Självtest före användarkommandon. Fel ger stopp, aldrig osandboxad fallback.
- SHA-256-kontroll av verktygsarkiv med `sha2` (beroenden låsta i `Cargo.lock`).
- Sandboxad HTTPS-hämtning och uppackning, utan globala installationer.

Rust har nu även **lokal Git-skanning, central CVE-status och SBOM-inventarium i
SQLite**, parallella jobb, felklassificering och begränsade retries.

**Nytt:** åtgärdskö, Critical-larm, batchgodkännande, tidsfönster och auditlogg via CLI.
**Nytt:** en första fix-exekverare för godkända, direkta beroendeversionsbyten.
**Återstår:** kodmigrering/ersättning, GitLab-API och webbvy. Skanningen och
beslutskön startar inte fixar automatiskt; `factory run` krävs.
Rust-binären behöver inte Python. `serve` finns ännu inte i Rust.

Python-prototypen och dess valfria containerfiler behålls som referens. Se
[tidigare prototypinstruktioner](docs/python-prototype.md); de beskriver inte den
nya Rust-versionen. Använd inte prototypens värdkörda byggpipeline för obetrodd kod.

## Bygg och testa

Rust/Cargo behövs för att bygga utvecklingsversionen. Slutanvändaren kommer att
kunna köra en färdig plattformsspecifik binär utan Rust-installation.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
./target/release/upgrade-lab sandbox doctor
```

Testerna på macOS kör **riktig Seatbelt**, inte simulerad sandbox. De kontrollerar
filåtkomst, barnprocessers begränsningar, nekad respektive explicit tillåten lokal
TCP-anslutning samt timeout. `doctor` kontrollerar filåtkomst och arv; det gör ännu
inte nätverksprovet. Om OS-backenden inte fungerar misslyckas testerna, de hoppas
inte över i tysthet.

## Snabbstart: verkligt end-to-end-test på macOS ARM64

```sh
./target/release/upgrade-lab tools bootstrap
./target/release/upgrade-lab smoke --network
```

`bootstrap` hämtar de fast valda arkiven i `tools/macos-aarch64.json`, kontrollerar
SHA-256 och installerar utan Homebrew eller Docker. Om ett verktyg redan finns
måste dess installationskvitto matcha katalogens arkivhash. Det är inte en
omhashning av installerade filer. Katalogen gäller bara macOS ARM64:

- Temurin JDK 21.0.13.1+2
- Apache Maven 3.9.9
- Trivy 0.76.2

Utgivarnas release-metadata används som källa, inte kryptografiskt verifierade
utgivarsignaturer. För Maven verifierades först utgivarens SHA-512, varefter
SHA-256 beräknades från samma arkiv. Ursprung dokumenteras i katalogen.

Varje `smoke` skapar ett nytt testrepo under `.lab/smoke-runs/<id>/` och sparar
bygglogg, SBOM-logg, skanningslogg samt `report.json`. Exemplet har två JUnit-tester
och det äldre testberoendet commons-lang3 3.12.0. Körningen måste hitta det kända
fyndet **CVE-2025-48924**. Status `completed_with_findings` innebär att testkedjan
fungerar, **inte** att repot är säkert. Inga uppgraderingar, godkännanden eller MR:er
utförs av smoke-kommandot. Målversionen 3.18.0 rapporteras från skanningsdatabasen.

När beroenden och Trivy-databasen är cachade kan samma test köras utan nätverk:

```sh
./target/release/upgrade-lab smoke
```

Nätverket nekas då av Seatbelt. Bygget kör Maven offline. CycloneDX-pluginen
kräver Mavens online-läge även med varm cache, så den startas utan `-o`, men
sandboxens nätverksförbud gäller fortfarande. Saknad cache ger fel, inte fallback
till nätåtkomst. Trivy använder då befintlig databas utan uppdatering.

**Verifierat på den här maskinen:** installation av alla tre riktiga arkiv,
versionskontroller, två godkända Java-tester, CycloneDX 1.6-SBOM, ett verkligt
Trivy-fynd och därefter en komplett upprepning med nätverket avstängt.

## Samlad CVE-status över 20 repon

Skapa nya, separata Rust-testrepon. Befintliga Python-repon i `.lab/repos/` lämnas
orörda. Alla 20 nya repon har samma avsiktligt gamla beroende och två Java-tester;
de representerar ännu inte olika verksamhetstjänster eller individuella felscenarier.

```sh
./target/release/upgrade-lab repos init-examples
./target/release/upgrade-lab scan --config .lab/repositories.json --workers 4 --network
./target/release/upgrade-lab status
./target/release/upgrade-lab status --repo order-service --json
./target/release/upgrade-lab status --cve CVE-2025-48924 --json
```

`init-examples` skapar `.lab/rust-repos/` och `.lab/repositories.json`. Befintliga
mappar och en befintlig konfigurationsfil skrivs inte över. Om kommandot avbryts
mitt i initiering kan ofullständiga exempel behöva återskapas manuellt.
Ändra konfigurationen för egna lokala Git-repon och brancher:

```json
{
  "repositories": [
    {"name":"order-service", "path":".lab/rust-repos/order-service", "branches":["main","develop"]}
  ]
}
```

Sökvägar är relativa aktuell arbetskatalog, inte konfigurationsfilens mapp. `..`
avvisas. Namn+branch är inventariets identitet; samma identitet kan inte senare
peka på en annan lokal sökväg. Brancher stöds för närvarande som main/develop.
Ingen kloning från fjärrserver ingår ännu.

### Körning och resultat

- Max åtta samtidiga jobb (standard fyra).
- Endast branchens exakta, committade Git-snapshot skannas; lokala ändringar och
  otrackade filer följer inte med. Källrepot lämnas orört.
- Git och uppackning körs också under Seatbelt. Apple Git/Xcode CommandLineTools
  behöver finnas; Rust-integrerad Git eller medlevererad Git återstår.
- Bygg/test, CycloneDX och Trivy körs i jobbets separata skrivbara katalog.
- Databas: `.lab/scans.sqlite`, med historik per repo, branch och commit.
- Rapport, källsnapshot, SBOM och loggar: `.lab/scans/<id>/`.
- `scan` skriver ett JSON-objekt med `runs` och `infrastructure_errors` till stdout;
  framsteg går till stderr. Exitkod 1 betyder att något jobb misslyckats.
- SBOM lagras centralt endast efter en fullständigt lyckad skanning. Misslyckad
  körnings partiella artefakter kan finnas i jobbkatalogen, men ersätter inte
  tidigare verifierade inventarieposter.

Utan `--network` körs nätverksnekat med befintliga cacher, precis som smoke-testet.
Kör först en online-smoke på en tom installation för att värma beroenden/databas.
Ingen scannerdata skickas upp som en rapporttjänst, men nätverksaktiverade verktyg
kan kontakta sina beroende-/databaskällor. Jobben ska inte få produktionshemligheter.

`status` visar tabell med severity-antal och senaste lyckade commit. `--json` ger
fulla fynd, tidsstämplar, incidenter och loggsökvägar. `--repo` filtrerar repo;
`--cve` filtrerar fyndlistan men repo-tabellens totalsiffror gäller fortfarande alla
fynd för valda repon. `--max-age-seconds` styr färskhetsgränsen (standard ett dygn).

**Säker statusmodell:**
- Aldrig lyckad skanning: severity-antal är okända (`—`/null), inte noll.
- Misslyckad eller pågående senaste skanning: senaste lyckade fynd visas som STALE.
- Äldre än färskhetsgränsen: STALE även om senaste körningen lyckades.
- Lyckad skanning kan fortfarande ha CVE:er. Den betyder inte ”säker”.
- Färskhet gäller insamlingstid; den garanterar inte att branch-head eller
  sårbarhetsdatabasen är oförändrad/aktuell. Scanner/databasmetadata sparas där den
  finns; offline-läge använder uttryckligen cachad databas.

### När skanning misslyckas

Fel innehåller steg (`source`, `build`, `sbom`, `vulnerability_scan`), kategori,
meddelande och loggsökväg. Kategorisering bygger delvis på loggtext och är
vägledande, inte säker diagnos. Endast kända tillfälliga nätfel med aktiverat
nätverk får automatiska retries: högst två extra försök, med 1/2 sekunders väntan.
`--retries 0` stänger av dem. Behörighetsfel, sandboxfel, byggfel, timeout och
saknad cache leder inte till automatiskt kringgående eller kodändringar.

Efter slutligt fel skapas/uppdateras en **lokal teknisk incident** per
repo/branch/felkategori. En ny lyckad skanning löser äldre tekniska incidenter;
själva CVE:erna försvinner inte om de fortfarande finns i skanningen. Loggar från
varje faktiskt försök sparas. Förlorad databasåtkomst rapporteras som separat
infrastrukturfel, inte framgång. Avbrutna processer kan lämna `running`-poster;
automatisk återhämtning av sådana jobb återstår.

Inga GitLab-ärenden eller agentjobb skapas ännu. Det här är avsiktligt: först
spårbara, kontrollerade fel utan agent. Ingen gammal SBOM återskannas automatiskt
som fallback och inget misslyckat jobb presenteras som en ny lyckad skanning.

Exportera alla lyckade repo/commit-SBOM:er i ett centralt inventarium:

```sh
./target/release/upgrade-lab inventory > .lab/central-inventory.json
```

Exporten innehåller original-CycloneDX per snapshot med proveniens; en enda
sammanfogad CycloneDX-export är ännu inte portad till Rust. Det är källinventarium,
inte inventarium över vad som faktiskt är driftsatt.

## Åtgärdskö: Critical → larm → godkännande → fix

Följande kökommandon lagrar beslut och visar spärrar. De startar inga fixar.
Versionsbyten kan därefter köras uttryckligen med `factory run`, se nedan.

```sh
./target/release/upgrade-lab queue refresh
./target/release/upgrade-lab queue list
./target/release/upgrade-lab queue list --json
./target/release/upgrade-lab queue alerts
./target/release/upgrade-lab queue audit
```

Efter en lyckad skanning uppdateras kön automatiskt. `refresh` fyller även kön
från tidigare sparade resultat utan en ny skanning. Befintliga förslag återanvänds
när innehållet är oförändrat. Våra 20 exempel har var sitt Medium-fynd och får ett
versionsförslag till 3.18.0 — **ännu inget godkännande**.

- Critical ger terminal-larm och en auditpost, även när ingen fixversion finns.
  `alerts` visar alla aktuella Critical-fynd, även tydligt markerat inaktuella.
  Larmhändelser dedupliceras per repo/branch/commit/CVE/paket/version. Inget
  e-post-, Slack- eller annat push-larm är anslutet ännu.
- Övriga fynd samlas för planerad hantering.
- Ett automatiskt versionsförslag skapas endast när skannern anger en enda
  explicit fixversion. Annars finns fyndet kvar i status/alerts för manuellt
  åtgärdsval; fabriken gissar inte version eller lösning.

### Välj åtgärd och mandat

Ett förslag binds till repo, branch, exakt skannad commit, CVE, paket/version,
severity, vald lösning, kodändringsmandat och verifieringskrav. Hela innehållet
har ett SHA-256-ID. Tillgängliga lösningstyper i beslutsmodellen:

- `upgrade`: versionsbyte, med eller utan explicit kodändringsmandat.
- `adapt_code`: anpassning av koden enligt beskrivet mandat.
- `replace`: ersätt beroendet; ange även `replacement`.
- `remove`: ta bort beroendet och anpassa kod.
- `mitigate`: tillfällig skyddsåtgärd med uttryckligt mandat.

Detta är **beskrivningar av godkända uppdrag**, inte färdiga implementationsrecept.
Riskacceptans avvisas tills ägare/utgångstid och uppföljning är implementerade.

För att välja en annan lösning: kopiera `proposal`-objektet för rätt rad från
`queue list --json` till en fil, beskriv åtgärden och skicka in den:

```sh
./target/release/upgrade-lab queue propose --file .lab/proposal.json --by Tobias
```

Behåll fyndets identitet och observerade värden. För `replace`/`adapt_code`/`remove`
krävs `code_changes: true` och verifieringskravet `code_review`. Alla förslag måste
kräva `build`, `tests`, `sbom` och `security_scan`. Använd `evidence_fixed_version`
för skannerns oförändrade fixversionssträng (även tom sträng om fix saknas), särskilt
om din egen målversion skiljer sig från skannerns förslag. Utan det fältet förutsätts
ett versionsförslags målversion vara den fixversion skannern rapporterade.

`main` tillåter normalt bara versionsbyten. Kod-/andra ändringar måste gå mot ett
**separat skannat develop-underlag**, eller ha `hotfix_exception: true` för ett
Critical-fynd. Undantaget ingår i det innehåll du godkänner; det beviljas aldrig
automatiskt. Ett byte av målbranch kräver ett eget förslag med den branchens fynd
så att vi inte låtsas att main och develop har samma kod.

Ändra inte ett gammalt förslag i databasen. Skapa ett nytt med `supersedes` satt
till det gamla fullständiga ID:t. Det blockerar tidigare godkännanden av det gamla
mandatet och kräver ett nytt beslut. En redan godkänd batch behöver också återkallas
innan samma paket får en annan aktiv åtgärd/tidpunkt.

### Gemensamt godkännande och tidsfönster

Använd fullständiga ID:n från kön. Välj alla ännu obeslutade, giltiga förslag eller
en kommaseparerad lista med `--ids ID,ID`. Konflikter/alternativ för samma fynd
måste väljas uttryckligen; en batch med motstridiga uppdrag avvisas i sin helhet.

Critical kan godkännas för omedelbar hantering (gäller en timme):

```sh
./target/release/upgrade-lab queue approve --ids FULLSTANDIGT_ID --by Tobias --now
```

För övriga väljs ett planerat fönster med Unix-tid i **sekunder** (UTC-tidsstämplar,
inte lokal klocktext). Ersätt platshållarna med verkliga framtida tider:

```sh
./target/release/upgrade-lab queue approve --all --by Tobias \
  --from START_UNIX_SECONDS --until END_UNIX_SECONDS
./target/release/upgrade-lab queue ready
```

`ready` visar samtliga batcher och blockerande orsaker, inte bara körklara jobb.
`eligible_by_scan_evidence` kräver att tidsfönstret är öppet, godkännandet inte är
utgånget/återkallat och att senaste skanning lyckades för samma commit/fynd/severity/
fixversionsunderlag inom 24 timmar. Ändrat eller saknat underlag stoppar batchen.
Flera repon godkänns i **en atomisk batch**, inte genom enskilda repo-godkännanden.

`ready` granskar databasens underlag, inte Git-head i realtid. Exekveraren gör
ytterligare Git-/diffkontroller och en atomisk claim. Redan claimade batcher
blockeras för återkörning och visas med `execution_started: true`.
Godkännandet binds också till mandatpolicy och den inbyggda verktygskatalogens hash;
ändrad katalog eller gamla obundna beslut kräver nytt godkännande.
`merge_authorized` är alltid false. Ett godkänt förslag stänger inte CVE-fyndet.

Återkalla ett godkännande med motivering:

```sh
./target/release/upgrade-lab queue revoke --batch FULLSTANDIGT_BATCH_ID \
  --by Tobias --reason "Ändrad plan eller åtgärd"
```

Förslag, batchbeslut, återkallelser och auditposter ligger i `.lab/scans.sqlite`.
Databastriggers skyddar mot normal ändring/radering av beslutshistorik. Detta är
**lokal spårbarhet, inte manipulationssäker revision**: `--by` är inte autentisering,
offline DB-administratörer kan ändra filen och ingen signerad extern logg finns.

## Verkställ en godkänd batch

```sh
./target/release/upgrade-lab factory run --batch FULLSTANDIGT_BATCH_ID --workers 2 --network
./target/release/upgrade-lab factory status
```

Detta kräver ett uttryckligt godkännande inom öppet tidsfönster. Ingen schemaläggare
startar batchen automatiskt ännu. Utan `--network` används befintliga cacher och
nätverket nekas. Max fyra samtidiga repogrupper. Ingen agent används.

Den första exekveraren stöder bara `upgrade` med `code_changes: false`, en vanlig
POM och explicita direkta beroendeversioner. Kodanpassning, ersättning/borttagning,
properties, BOM/parent, transitiva och multimoduluppgraderingar lämnas till manuell
hantering — mandatet breddas aldrig automatiskt. Ett unsupported kodmandat avvisas
innan claim; unsupported POM-struktur upptäcks per repo som `manual_required`.

Kontroller och resultat:

- Godkännande, återkallelse, giltighet, scan-underlag och verktygskatalog kontrolleras.
- Atomisk batch-claim och lås per registrerad reposökväg förhindrar dubbla körningar.
- Faktisk målbranch-head måste fortfarande motsvara den godkända committen.
- En **fristående Git-klon** skapas per repo/målbranch under `.lab/executions/`.
  Endast klonens kandidatbranch ändras. Originalrepo och dess brancher är read-only.
- Enbart exakta godkända versionstexter i `pom.xml` ändras. Formatering och övrigt
  innehåll bevaras. Kandidatens `.git` skyddas read-only under Maven/Trivy-körning.
- Bygg/test, CycloneDX och Trivy körs sandboxat. Krävda tester måste köras.
- Avsedda versioner måste finnas i SBOM. Kvarvarande fynd på uppgraderade paket
  och nya/eskalerade HIGH/CRITICAL-fynd stoppar kandidaten.
- Diff, filmoder, Git-head och exakt committad POM kontrolleras igen. Godkännandet
  och source-head kontrolleras mellan steg och efter verifiering.
- Framgång ger `verified_candidate`; ytterligare transitiva beroendeförändringar
  ger `awaiting_dependency_review`. Båda är lokala kandidater, inte merge-beslut.
- Varje grupp får loggar och `report.json`. Fel stoppar inte automatiskt övriga
  giltiga grupper. Slutrapporten visar varje resultat.
- Kandidat-SBOM sparas separat och exporteras som `candidate_snapshots` med roll,
  målbranch, commit och verifieringsstatus. Den ersätter inte source-branch-SBOM.

Det görs **ingen push, MR eller merge**. Inga CVE:er stängs på målbranchen bara för
att en kandidat blivit grön. Kandidatens egen Git-katalog/branch/commit anges i
`factory status`; originalets `git branch` visar därför inte kandidatbranchen.

En batch kan claimas endast en gång. Efter fel krävs ett nytt kontrollerat beslut;
ingen automatisk replay sker. En krasch efter claim behåller `running` och lås för
manuell utredning. Automatisk återhämtning, avbrytning och lease-hantering återstår.
Återkallelse stoppar vid nästa kontroll, inte omedelbart mitt i en pågående process.

**Testat:** 37 standardtester samt ett separat verkligt integrationstest som
uppgraderar ett temporärt testrepo från commons-lang3 3.12.0 till 3.18.0, bygger,
testar, producerar SBOM och skannar med Trivy. Det kontrollerar att originalets
Git-head/POM är oförändrade, att målbranchens CVE fortfarande finns i status och
att samma batch inte kan köras igen. Integrationstestet kräver bootstrap/cachad DB:

```sh
cargo test execution::tests::real_approved_upgrade_does_not_modify_original_or_close_main_finding -- --ignored --nocapture
```

Det testgodkännandet finns endast i en temporär databas och godkänner inte dina
20 väntande åtgärder. Implementationens kvarvarande säkerhetsbegränsningar nedan
(gemensam cache, processgrupper och avsaknad av hårda kvoter) gäller även fabriken.

## Kör ett CLI-kommando sandboxat

```sh
./target/release/upgrade-lab sandbox run -- /bin/echo sandbox-ok
./target/release/upgrade-lab sandbox run --timeout 5 -- /bin/sh -c 'while :; do :; done'
```

Ge bara det aktuella jobbet nödvändiga sökvägar. Sökvägar måste finnas; de
normaliseras innan profilen genereras:

```sh
./target/release/upgrade-lab sandbox run \
  --read /absolut/sokvag/till/input \
  --write /absolut/sokvag/till/jobb \
  --timeout 60 -- /bin/sh -c 'cat "$1/data.txt" > "$2/result.txt"' \
  job /absolut/sokvag/till/input /absolut/sokvag/till/jobb
```

Programmet måste anges med absolut sökväg. Själva programfilen blir läsbar och
körbar, men inte automatiskt hela dess installationskatalog. Bibliotek och andra
verktyg utanför systemets runtime måste tillåtas uttryckligen. Miljön är rensad;
HOME och TMPDIR pekar på jobbets tillfälliga katalog. Godtyckliga värdvariabler som
GitLab-token följer inte med. `tools run` nedan sätter en kontrollerad
JDK/Maven-miljö utan att ärva värdens miljö.

Nätverk är avstängt. `--network` tillåter utgående trafik, **inte** en begränsad
lista av domäner. Använd inte flaggan när ett jobb hanterar hemligheter.

Vanliga kommandon returnerar sin exitkod; timeout ger 124. Terminalutskrift
begränsas till 64 KiB per ström; de tillfälliga loggfilerna raderas efteråt.

## Installera verktyg i appens egen katalog

Välj officiella arkiv för **macOS och rätt CPU-arkitektur**. Ta SHA-256 från en
betrodd källa; en hash från samma komprometterade källa skyddar inte mot
leverantörsangrepp. Inga påhittade kontrollsummor eller automatiskt valda versioner
används. Du kan använda den granskbara katalogen ovan eller ange egna arkiv.
Ersätt platshållarna nedan med verkliga värden:

```sh
./target/release/upgrade-lab tools install jdk JDK_VERSION \
  --archive /absolut/sokvag/jdk.tar.gz --sha256 BETRODD_SHA256
./target/release/upgrade-lab tools install maven MAVEN_VERSION \
  --url https://officiell-server/maven.tar.gz --sha256 BETRODD_SHA256
./target/release/upgrade-lab tools install trivy TRIVY_VERSION \
  --archive /absolut/sokvag/trivy.tar.gz --sha256 BETRODD_SHA256
```

Arkivet kopieras till staging (eller hämtas med sandboxad system-curl), verifieras
med SHA-256 och packas upp med sandboxad system-tar. Absoluta sökvägar, `..`,
externa/absoluta symlänkar och specialfiler avvisas. Uppackning har inget nätverk.
Befintliga installationer skrivs inte över. Det förutsätter macOS systemverktyg
`/usr/bin/curl` och `/usr/bin/tar`, inte Homebrew-versioner.

Verktyg ligger i `.lab/tools/<kind>/<version>-<os>-<arch>/`. Ett installationskvitto
sparar versionsetikett och arkivhash. Etiketten bevisar inte verktygets verkliga
version: kontrollera `--version` separat. Installerade filer är inte signerade eller
omhashade vid varje körning. Katalogen ska endast ändras av den betrodda appen.

```sh
./target/release/upgrade-lab tools run jdk JDK_VERSION -- -version
./target/release/upgrade-lab tools run maven MAVEN_VERSION --jdk JDK_VERSION -- --version
./target/release/upgrade-lab tools run trivy TRIVY_VERSION -- --version
```

Maven får bara läsåtkomst till sin egen och JDK:ns installation. Kontrollerade
JAVA_HOME/PATH sätts och beroendecachen pekar på `.lab/cache/maven/repository`.
Trivy får en egen `.lab/cache/trivy`. Nätverk är fortfarande avstängt om det inte
uttryckligen aktiveras. För ett betrott testrepo:

```sh
./target/release/upgrade-lab tools run maven MAVEN_VERSION --jdk JDK_VERSION \
  --repo /absolut/sokvag/till/testrepo --network -- -B clean verify
```

Det ger skrivåtkomst till **just den repokopian** och verktygscachen, inte till
hemkatalogen. Välj en separat arbetskopia, inte ett repo med hemligheter. Appens
övergripande datakatalog eller en förälder till tool-katalogen avvisas som repo.
Nuvarande verktygskörning har 15 minuters timeout. För enbart versionskontroll
behövs varken repo eller nätverk. Cache delas mellan jobb; jobbvis cacheisolering
återstår. Ingen `~/.m2/settings.xml` eller privat registry-konfiguration ärvs.

Installationskedjan testas även med ett litet lokalt testarkiv och ett harmlöst
testverktyg. Tar-arkiv stöds; inga pkg-installationer eller zip-installationsflöden
ingår. Arkivlistan begränsas till 16 MiB, men total uppackad storlek har ännu ingen kvot.

## Säkerhetsgränser

Det här är en tidig implementation, inte en säkerhetsgranskad byggplattform:

- Sandboxen är en OS-policy, inte en VM. Den bygger på macOS säkerhetsmekanismer.
- Systemets runtime är läsbar. Filmetadata är generellt läsbar; det är inte en
  garanti för att dölja filnamn eller maskininformation.
- Alla filgrants är additiva. En skrivbar föräldrakatalog gör även dess barn
  skrivbara; ge inte en bred grant och förvänta dig att en smalare read-grant
  gör ett barn read-only. Hemkatalogen och filsystemroten ska inte exponeras.
  En grant av `/` avvisas uttryckligen.
- CPU/minne och loggfilsstorlek har ännu inte hårda kvoter. Visningsgränsen för
  loggar begränsar inte förbrukat diskutrymme.
- Timeout städar processgruppen, men är inte en garanti mot barnprocesser som
  aktivt bryter sig ur gruppen. Starkare livscykelhantering återstår.
- Varje kommando behöver fortfarande en korrekt, snäv uppsättning filgrants.
- Seatbelt-gränssnittet är föråldrat och måste regressionstestas på stödda macOS.
- **Linux-backenden är inte implementerad:** där vägrar programmet köra jobb.
  Planerad backend är Bubblewrap + seccomp, enligt mönstret i Codex.

## Arkitektur framåt

```text
Rust-app: API/UI, SQLite, GitLab, policy och godkännanden
                 ↓
       Tool manager + jobbhanterare
                 ↓
     Seatbelt (macOS) / Bubblewrap (Linux)
                 ↓
          Java/Maven och Trivy
```

Nästa steg är GitLab-adapter för granskbara MR:er och felärenden, schemalagd körning
samt kontrollerade recept/agentmandat för mer än direkta versionsbyten. Byggworkers
behöver hårdare resurs-/cacheisolering
innan godtycklig obetrodd kod kan hanteras.
GitLab-token ska alltid hållas utanför byggjobben.

Referensarkitektur studerad i `../codex/codex-rs/sandboxing/` och
`../codex/codex-rs/linux-sandbox/`. Vår minimala Seatbelt-policy är egen kod;
Codex hela implementation har inte kopierats eller integrerats.
