# ÚPVS IAM STS (Security Token Service)

Ukážková implementácia IAM STS postavená na kvalitných a overených open-source riešeniach kompatibilná s aktuálnou IAM system-to-system integráciou (SAML 2.0) na portáli ÚPVS (slovensko.sk)

## Hlavné funkcie
- Kompatibilné so súčasným ÚPVS IAM pre system-to-system integrácie (dokáže spracovať rovnaký request a vráti kompatibilný response)
- Ukážka škálovateľného úložiska pre klúče (redis)
- Dockerfile pre nasadenie a horizontálne škálovanie v modernom CI/CD prostredí
- Žiadne uzavreté technológie (všetko opensource a voľné licencie)
- EUPL licencia (ako vyžaduje [§ 15 ods. 2 písm. d) bod
  1 zákona č. 95/2019 Z. z.](https://www.slov-lex.sk/ezbierky-fe/pravne-predpisy/SK/ZZ/2019/95%20/?ucinnost=03.02.2026#paragraf-15.odsek-2.pismeno-d.bod-1))
- Nestojí to [17 miliónov eur](https://360tka.sk/videos/ani-chat-gpt-o-nej-nevedel-hovoria-it-odbornici-ooo-firme-od-ktorej-chce-migalov-rezort-system-za-17-milionov)

## Technológie

- **Java**
- **Spring Boot** - aplikačný framework
- **Apache CXF** - WS-Trust a WS-Security implementácia
- **Redis** - allowlist certifikátov (serial number)
- **Maven** - build
- **Docker** - kontajnerizácia

## Architektúra

Spring Boot aplikácia s Apache CXF (WS-Trust/WS-Security). Prijíma a overuje podpísané SOAP požiadavky, overuje certifikát cez Redis a vracia SAML assertion.

**Komponenty:** STSApp (entry point), STSConfiguration (konfigurácia), AddUPVSSamlAssertionsHandler (SAML atribúty), RedisCertValidator (certifikáty)

## Inštalácia a spustenie

### Maven

```bash
# Kompilácia
mvn clean compile

# Balenie do JAR
mvn clean package -DskipTests

# Spustenie
mvn spring-boot:run
```

## Testovacia ukážka

1. Spustenie služby 
```
docker compose up
```
2. Povolenie klúča so serial number, ktorý je v ukážkovom requeste.  
```
docker exec -it sts-redis redis-cli SET cert:serial:9379126337400755137 "1"
```

3. Test request na STS službu
```bash
curl -X POST http://localhost:8080/services/STS -d @sts-request.xml
```

4. Zmazanie certifikátu z Redis
```bash
docker exec -it sts-redis redis-cli DEL cert:serial:9379126337400755137
```

## Bezpečnostné upozornenia

⚠️ **Toto je Proof of Concept:**

1. **Hardcoded heslá** - Keystore password je "changeit"
2. **Timestamp strictness** - Vypnuté pre debugovanie (TIMESTAMP_STRICT=false)
3. **Hardcoded dáta** - SAML atribúty obsahujú testovacie dáta
4. **Replay cache** - Aktuálna implementácia nie je vhodná pre multi-instance nasadenie

## TODOs

- [ ] Zmeniť hardcoded keystore password
- [ ] Implementovať LDAP/Redis integráciu pre reálne dáta 
- [ ] Spraviť replay cache pre multi-instance scaling
- [ ] Povoliť TIMESTAMP_STRICT v produkcii

## Licencia

Tento projekt je licencovaný pod [EUPL-1.2](LICENSE) (European Union Public Licence 1.2).
