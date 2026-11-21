# Upgrade Lab

Lokalt labb för gemensamt godkända uppgraderingar av 20 Java-repon.
**All kod, Git, Python, Java 21, Maven och Trivy körs i container.**
På värden behövs bara Docker med Compose. Installera inte Maven/Trivy med Homebrew.

## Starta

```sh
docker compose build
docker compose run --rm lab python3 lab.py init
docker compose run --rm lab python3 lab.py prepare
docker compose up -d
```

API: http://127.0.0.1:8081/api/v4/projects

Porten på värden är 8081 för att undvika SSH-tunneln på 8080. Byt vid behov:

```sh
LAB_PORT=8082 docker compose up -d
```

Loggar och tester:

```sh
docker compose logs -f lab
docker compose run --rm lab python3 -m unittest -v
```

Ingen separat GitLab-server behövs. API:t simulerar projekt, branches, MR:er och
ärenden. Brancher är verkliga Git-brancher; MR:er/ärenden är JSON-poster och inga
riktiga GitLab-pipelines körs.

## Data och isolering

- `lab-data`: repon, planer, resultat, loggar, SBOM och SQLite-inventarium.
- `maven-cache`: nedladdade Maven-beroenden.
- `trivy-cache`: Trivys sårbarhetsdatabaser.
- Ingen bind-mount av projektet eller hemkataloger, ingen Docker-socket.
- Icke-root-användare, read-only rootfilsystem, tillfällig `/tmp`, borttagna
  Linux capabilities, no-new-privileges och resursgränser.
- Bara API-porten exponeras, och enbart på värdens loopback-adress.
- Maven Central och Trivys databaser kräver utgående nätåtkomst.

**Viktigt:** Maven-plugins och tester kör kod. Containern skyddar inte andra filer
inne i dess egna datavolymer. Den här versionen är avsedd för betrodda exempelrepon,
inte fientlig kod eller fullständig isolering mellan repon. Separata kortlivade
byggcontainrar/VM:ar krävs för den hotmodellen. Inga produktionshemligheter ska
läggas i miljön.

Tidigare värddata i projektets `.lab/` importeras **inte** automatiskt. Docker får
ett nytt labb med interna sökvägar under `/app/.lab`. Gamla planer innehåller
absoluta värdsökvägar och ska inte återanvändas. Skapa/godkänn nya planer i containern.
Vanlig `docker compose down` behåller data; `docker compose down -v` raderar allt.

Imagen innehåller Maven 3.9.9, Java 21 och Trivy 0.58.2. Versionerna är fast valda,
inte ett påstående om senaste eller säkraste release. Uppdatera verktygsbilderna
regelbundet; image-digests är ännu inte låsta. Ändrad kod kräver `docker compose build`.

## Uppgraderingsbatch

`prepare` lägger in commons-lang3 3.12.0, ett JUnit-test, Surefire-plugin och
`develop`-brancher. De individuella felscenarierna i `lab_scenario` är fortfarande
planerad metadata, inte 20 olika implementerade fel.

```sh
docker compose run --rm lab python3 upgrades.py batch-plan \
  --config examples/batch.json --out .lab/batch.json
```

Exemplet väljer order-service/main och customer-service/develop; inventory-service
är bortvalt med `selected: false`. Läs planen inne i containern:

```sh
docker compose run --rm lab python3 -m json.tool .lab/batch.json
```

Godkänn och kör:

```sh
docker compose run --rm lab python3 upgrades.py approve .lab/batch.json --by ditt-namn
docker compose run --rm lab python3 upgrades.py batch-apply .lab/batch.json \
  --workers 4 --out .lab/results.json
```

För egna urval: kopiera exempelkonfigurationen till den skrivbara datavolymen och
redigera den där, exempelvis genom en containerkörd Python-process. Använd den
sedan som `--config .lab/min-batch.json`. Ändra aldrig en redan godkänd plan.
Flera beroenden i samma repo samlas i `changes`; samma repo kan ha en plan per
målbranch. En misslyckad uppgradering blockerar inte övriga jobb.

Godkännandet binds till versionsbyten, repo, målbranch och exakt utgångscommit.
Ändrad plan/policy eller flyttad målbranch kräver ny plan och nytt godkännande.
Arbetet sker i separata Git-worktrees och lämnar målbranch och befintlig arbetskopia
orörda. Kandidater får `upgrade/<plan-id>`-brancher. Samma plan kan inte appliceras
igen om dess branch finns; automatisk återupptagning är ännu inte implementerad.

Godkännarens namn är lokal testmetadata, inte autentiserad behörighet. Hashen är
inte en digital signatur. API:t har ingen autentisering och får inte exponeras
publikt. Direkt skapande av simulerade MR:er är inte en verifieringskontroll.

### Branchpolicy

- `main`: endast exakt godkända direkta beroendeversioner i `pom.xml`.
  Ingen källkod, tester, CI, parent, BOM eller andra POM-delar får ändras.
- `develop`: policyn medger framtida separat godkända migreringar, men den
  nuvarande motorn gör även här **bara direkta versionsbyten**.
- Maven-properties, dependencyManagement, multimoduländringar och transitiva
  uppgraderingsåtgärder stöds ännu inte. Motorn stoppar i stället för att gissa.
- En patch-/minorversion är inte automatiskt riskfri.

## Verifiera och producera SBOM

```sh
docker compose run --rm lab python3 verification.py .lab/batch.json --workers 2
```

Både baseline och kandidat verifieras:

1. `mvn clean verify`; Surefire/Failsafe-rapporter måste innehålla körda tester utan fel.
2. CycloneDX Maven-plugin 2.9.1 producerar SBOM med upplösta beroenden.
3. De förväntade beroendeversionerna kontrolleras i SBOM.
4. `trivy sbom` körs med verklig sårbarhetsdata.
5. Kvarvarande fynd på uppgraderade direkta beroenden och nya HIGH/CRITICAL-fynd
   stoppar jobbet. Övriga befintliga fynd räknas i rapporten.
6. Beroendeskillnader redovisas för granskning.

Rapporter och loggar: `.lab/verification/<plan-id>/report.json`, samt SBOM,
byggloggar och Trivy-resultat i respektive `baseline/` och `candidate/`.
Saknade verktyg ger `blocked`, kontrollfel ger `failed`, lyckad teknisk verifiering
slutar i `awaiting_dependency_review`. Automatisk MR/ärendehantering återstår.
Exemplets målversion 3.17.0 är **inte en verifierad säker fix** och kan stoppas
av skanningen. Grön skanning är heller inte en garanti för frånvaro av sårbarheter.

SBOM sparas centralt med repo, branch, commit och baseline/candidate-roll. Kandidaten
ersätter inte standardgrenens eller den driftsatta versionens inventarium.

```sh
docker compose run --rm lab python3 inventory.py --out .lab/inventory.json
docker compose run --rm lab python3 inventory.py --format cyclonedx --out .lab/central-sbom.json
```

Inventarieexporten behåller original-SBOM. Samlad CycloneDX innehåller snapshots
med proveniens och separata komponentreferenser; det är historik, inte aktuell
driftsättning. Läs exempelvis exporten med:

```sh
docker compose run --rm lab python3 -m json.tool .lab/central-sbom.json
```

## API

JSON-requester, inte hela GitLabs exakta schema:

- `GET /api/v4/projects` (search, page, per_page)
- `GET /api/v4/projects/:id`
- `GET/POST /api/v4/projects/:id/repository/branches`
- `GET/POST /api/v4/projects/:id/merge_requests`
- `GET/POST /api/v4/projects/:id/issues`

Numeriskt projekt-ID eller URL-kodat namespace/namn stöds. `local_path` är ett
labbspecifikt fält, inte GitLabs klonprotokoll. Initiering behåller befintlig data.
`prepare` kräver rena arbetskopior på main och avancerar develop bara om den inte
har egna ändringar; äldre planer blir ogiltiga när fixture-commits tillkommer.

## Tester och återstående arbete

Testerna skapar tillfälliga repon och ändrar inte labbrepona. Verifieringstesterna
använder tydligt markerade testdubblar för Maven/Trivy. De ersätter inte en verklig
bygg- och skanningskörning.

Återstår: webbvy, schemalagda skanningar, autentiserad granskning, isolerade
byggworkers för obetrodd kod, automatisk MR/ärendehantering och kontrollerad
agenthantering. Batchgodkännande och merge är separata beslut.
