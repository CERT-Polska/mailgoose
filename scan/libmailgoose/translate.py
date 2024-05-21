import copy
import re
from typing import Callable, List, Optional, Tuple

from .language import Language
from .scan import DKIMScanResult, DomainScanResult, ScanResult

PLACEHOLDER = "__PLACEHOLDER__"
SKIP_PLACEHOLDER = "__SKIP_PLACEHOLDER__"


TRANSLATIONS = {
    Language.lt_LT: [  # type: ignore
        (
            "SPF '~all' or '-all' directive not found. We recommend adding it, as it describes "
            "what should happen with messages that fail SPF verification. For example, "
            "'-all' will tell the recipient server to drop such messages.",
            "Nerasta SPF įrašo su '~all' arba '-all' direktyva. Rekomenduojame ją pridėti, nes ji nurodo, "
            "kas turėtų atsitikti su pranešimais, kurie nepavyksta SPF verifikacijai. Pavyzdžiui, "
            "'-all' informuos gavėjo serverį atmesti tokius pranešimus.",
        ),
        (
            "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
            "Nerastas galiojantis SPF įrašas. Rekomenduojame naudoti visus tris mechanizmus: SPF, DKIM ir DMARC, "
            "kad sumažintumėte sėkmingų elektroninių laiškų klastojimo galimybę.",
        ),
        (
            "Multiple SPF records found. We recommend leaving only one, as multiple SPF records "
            "can cause problems with some SPF implementations.",
            "Rasta daugiau nei vieną SPF įrašą. Rekomenduojame palikti tik vieną, nes keli SPF įrašai "
            "gali sukelti problemų su kai kuriais SPF patvirtinimais.",
        ),
        (
            f"The SPF record's include chain has a reference to the {PLACEHOLDER} domain that doesn't "
            "have an SPF record. When using directives such as 'include' or 'redirect' remember "
            "that the destination domain must have a correct SPF record.",
            f"SPF įrašo 'include' grandinė nurodo į domeną {PLACEHOLDER}, kuris neturi SPF įrašo. "
            "Naudojant direktyvas, tokias kaip 'include' arba 'redirect', prisiminkite, "
            "kad paskirties domenas turi turėti teisingą SPF įrašą.",
        ),
        (
            "SPF record causes too many void DNS lookups. Some implementations may require the number of "
            "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
            "are caused by directives such as 'mx' or 'include'.",
            "SPF įrašas sukelia per daug tuščių DNS paieškų. Kai kuriems įgyvendinimams gali prireikti, kad "
            "nepavykusių DNS paieškų (pvz., kurie nurodo neegzistuojantį domeną) skaičius būtų mažas. DNS paieškos "
            "sukeliamos direktivomis, tokiomis kaip 'mx' arba 'include'.",
        ),
        (
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain.",
            "SPF įrašas sukuria begalinį ciklą. Patikrinkite, ar 'include' arba 'redirect' direktyvos "
            "nesukuria ciklo, kai domenas nukreipia atgal į save ar ankstesnį domeną.",
        ),
        (
            "SPF record causes too many DNS lookups. The DNS lookups are caused by directives such as 'mx' or 'include'. "
            "The specification requires the number of DNS lookups to be lower or equal to 10 to decrease load on DNS servers.",
            "SPF įrašas sukelia per daug DNS paieškų. DNS paieškos sukeliamos direktyvomis, tokiomis kaip 'mx' arba 'include'. "
            "Specifikacija nurodo, kad DNS paieškų skaičius turi būti mažesnis arba lygus 10, kad būtų sumažintas "
            "apkrovimas DNS serveriams.",
        ),
        (
            "The ptr mechanism should not be used - https://tools.ietf.org/html/rfc7208#section-5.5",
            "Mechanizmas 'ptr' neturėtų būti naudojamas - https://tools.ietf.org/html/rfc7208#section-5.5",
        ),
        (
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
            "Nerastas galiojantis DMARC įrašas. Rekomenduojame naudoti visus tris mechanizmus: SPF, DKIM ir DMARC, "
            "kad sumažintumėte sėkmingų elektroninių laiškų klastojimo galimybę.",
        ),
        (
            "DMARC policy is 'none' and 'rua' is not set, which means that the DMARC setting is not effective.",
            "DMARC politika yra 'none', o 'rua' nėra nustatytas, tai reiškia, kad DMARC nustatymas nėra veiksmingas.",
        ),
        (
            f"The DMARC record must be located at {PLACEHOLDER}, not {PLACEHOLDER}",
            f"DMARC įrašas turi būti įdiegtas į {PLACEHOLDER}, o ne {PLACEHOLDER}.",
        ),
        (
            "There are multiple DMARC records. We recommend leaving only one, as multiple "
            "DMARC records can cause problems with some DMARC implementations.",
            "Yra keli DMARC įrašai. Rekomenduojame palikti tik vieną, nes keli DMARC įrašai gali sukelti problemų su kai kurių "
            "DMARC įgyvendinimais.",
        ),
        (
            "There is an SPF record instead of DMARC one on the '_dmarc' subdomain.",
            "Subdomene '_dmarc' yra SPF įrašas, o ne DMARC.",
        ),
        (
            "DMARC record uses an invalid tag. Please refer to https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 "
            "for the list of available tags.",
            "DMARC įrašas naudoja neteisingą žymą. Skaitykite https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 "
            "dėl prieinamų žymių sąrašo.",
        ),
        (
            "DMARC report URI is invalid. The report URI should be an e-mail address prefixed with mailto:.",
            "DMARC raportas URI yra neteisingas. Raportų adresas turi būti el. pašto adresas prasidedantis su mailto:.",
        ),
        (
            "The destination of a DMARC report URI does not indicate that it accepts reports for the domain.",
            "DMARC raporto adreso paskirtis nenurodo, kad jis priima raportus iš šio domeno.",
        ),
        (
            "Subdomain policy (sp=) should be reject for parked domains",
            "Subdomenų politika (sp=) turėtų būti nustatyta kaip reject parked domenams.",
        ),
        (
            "Policy (p=) should be reject for parked domains",
            "Politika (p=) turėtų būti nustatyta kaip reject nepanaudotiems domenams.",
        ),
        (
            "Unrelated TXT record found in the '_dmarc' subdomain. We recommend removing it, as such unrelated "
            "records may cause problems with some DMARC implementations.",
            "Rasti nepriklausomi TXT įrašai '_dmarc' subdomene. Rekomenduojame juos pašalinti, nes tokie nesusiję "
            "įrašai gali sukelti problemų su kai kuriomis DMARC implementacijomis.",
        ),
        (
            "Unrelated TXT record found in the '_dmarc' subdomain of a domain the record refers to. "
            "We recommend removing it, as such unrelated records may cause problems with some DMARC "
            "implementations.",
            "Rasti nesusiję TXT įrašai '_dmarc' subdomeno domeno, į kurį nukreiptas įrašas. Rekomenduojame juos pašalinti, "
            "nes toki neatsitinkantys įrašai gali sukelti problemų su kai kuriomis DMARC implementacijomis.",
        ),
        (
            "The domain of the email address in a DMARC report URI is missing MX records. That means, that this domain "
            "may not receive DMARC reports.",
            "DMARC raporto adreso el. pašto domenas neturi MX įrašų. Tai reiškia, kad šis domenas gali nebegauti DMARC raportų.",
        ),
        (
            "DMARC policy is 'none', which means that besides reporting no action will be taken. The policy describes what "
            "action the recipient server should take when noticing a message that doesn't pass the verification. 'quarantine' policy "
            "suggests the recipient server to flag the message as spam and 'reject' policy suggests the recipient "
            "server to reject the message. We recommend using the 'quarantine' or 'reject' policy.\n\n"
            "When testing the DMARC mechanism, to minimize the risk of correct messages not being delivered, "
            "the 'none' policy may be used. Such tests are recommended especially when the domain is used to "
            "send a large number of e-mails using various tools and not delivering a correct message is "
            "unacceptable. In such cases the reports should be closely monitored, and the target setting should "
            "be 'quarantine' or 'reject'.",
            "DMARC politika yra 'none', tai reiškia, kad be raportavimo nebus vykdoma jokia papildoma veikla. "
            "Politika apibūdina, kokį veiksmą turi atlikti gavėjo serveris pastebėjęs pranešimą, kuris nepasiekė patvirtinimo. "
            "Politika 'quarantine' siūlo gavėjo serveriui žymėti pranešimą kaip spam ir politika 'reject' siūlo gavėjo serveriui "
            "atmesti pranešimą. Rekomenduojame naudoti politiką 'quarantine' arba 'reject'.\n\n"
            "Testuojant DMARC mechanizmą, siekiant sumažinti riziką, kad teisingi pranešimai nebus pristatyti, "
            "gali būti naudojama 'none' politika. Tokie testai yra rekomenduojami ypač, kai domenas naudojamas "
            "siųsti didelį kiekį el. laiškų naudojant įvairias priemones, o neteisingo pranešimo pristatymas "
            "yra nepriimtinas. Tokiais atvejais raportai turėtų būti atidžiai stebimi, o nustatyti nustatymai "
            "turėtų būti 'quarantine' arba 'reject'.",
        ),
        (
            "rua tag (destination for aggregate reports) not found",
            "rua žymė (adresas agreguotų raportų nukreipimui) nerastas",
        ),
        (
            "Whitespace in domain name detected. Please provide a correct domain name.",
            "Rastas 'Whitespace' domeno pavadinime. Prašome pateikti teisingą domeno pavadinimą.",
        ),
        (
            f"Unexpected character in domain detected: {PLACEHOLDER}. Please provide a correct domain name.",
            f"Nenumatytas simbolis aptiktas domeno pavadinime: {PLACEHOLDER}. Prašome pateikti teisingą domeno pavadinimą.",
        ),
        (
            "Any text after the all mechanism is ignored",
            "Bet koks tekstas po 'all' mechanizmo yra ignoruojamas. Rekomenduojame jį pašalinti arba, "
            "jei jis yra būtinas konfigūracijos elementas, jį padėti prieš 'all' mechanizmą SPF įraše.",
        ),
        (
            "No DKIM signature found",
            "DKIM parašas nerastas. Rekomenduojame naudoti visus tris mechanizmus: SPF, DKIM ir DMARC, kad "
            "būtų sumažinta sėkmingo el. pašto pranešimo klastojimo galimybė.",
        ),
        (
            "Found an invalid DKIM signature",
            "Rastas neteisingas DKIM parašas.",
        ),
        (
            "SPF records containing macros aren't supported by the system yet.",
            "SPF įrašai, kuriuose yra macros, nėra palaikomi sistemos.",
        ),
        (
            f"The resolution lifetime expired after {PLACEHOLDER}",
            f"Rezoliucijos galiojimo laikas baigėsi po to {PLACEHOLDER}",
        ),
        (
            f"DMARC record at root of {PLACEHOLDER} has no effect",
            f"DMARC įrašas šakniniame {PLACEHOLDER} domene neturi jokio poveikio",
        ),
        (
            "Found a DMARC record that starts with whitespace. Please remove the whitespace, as some "
            "implementations may not process it correctly.",
            "Rastas DMARC įrašas, prasidedantis tarpais. Prašome pašalinti tarpus, kadangi kai kurios "
            "įgyvendinimo sistemos gali neteisingai juos apdoroti.",
        ),
        (f"{PLACEHOLDER} does not have any MX records", f"Domenas {PLACEHOLDER} neturi jokių MX įrašų."),
        (f"{PLACEHOLDER} does not have any A/AAAA records", f"Domenas {PLACEHOLDER} neturi jokių A/AAAA įrašų."),
        (
            f"{PLACEHOLDER} does not indicate that it accepts DMARC reports about {PLACEHOLDER} - Authorization record not found: {PLACEHOLDER}",
            f"Domenas {PLACEHOLDER} neatskleidžia, kad priima DMARC ataskaitas apie {PLACEHOLDER} - Autorizacijos įrašas nerastas: {PLACEHOLDER}."
            "Daugiau informacijos apie autorizacijos įrašus, kurie leidžia siųsti DMARC ataskaitas į kitą domeną, galima rasti adresu https://dmarc.org/2015/08/receiving-dmarc-reports-outside-your-domain/ .",
        ),
        (
            "SPF type DNS records found. Use of DNS Type SPF has been removed in the standards track version of SPF, RFC 7208. These records "
            f"should be removed and replaced with TXT records: {PLACEHOLDER}",
            "Rasti DNS įrašai, susiję su SPF. SPF tipo DNS įrašų naudojimas buvo pašalintas standartiniame SPF versijos, RFC 7208. "
            "Šie įrašai turėtų būti pašalinti ir pakeisti TXT įrašais: {PLACEHOLDER}.",
        ),
        (
            "Requested to scan a domain that is a public suffix, i.e. a domain such as .com where anybody could "
            "register their subdomain. Such domain don't have to have properly configured e-mail sender verification "
            "mechanisms. Please make sure you really wanted to check such domain and not its subdomain.",
            "Prašoma nuskaityti viešąjį sufiksą turintį domeną, t.y. domeną, tokį kaip .com, kurį gali registruoti bet kas. Toks domenas "
            "nebūtinai turi tinkamai sukonfigūruotus el. pašto siuntėjo patvirtinimo mechanizmus. Prašome patikrinti, ar tikrai norite patikrinti tokį domeną, o ne jo subdomeną.",
        ),
        (
            "Requested to scan a top-level domain. Top-level domains don't have to have properly configured e-mail sender "
            "verification mechanisms. Please make sure you really wanted to check such domain and not its subdomain."
            "Besides, the domain is not known to the Public Suffix List (https://publicsuffix.org/) - please verify whether "
            "it is correct.",
            "Prašoma nuskaityti top-level lygio domeną. top-level lygio domenai nebūtinai turi tinkamai sukonfigūruotus el. pašto siuntėjo patvirtinimo mechanizmus. "
            "Prašome patikrinti, ar tikrai norite patikrinti tokį domeną, o ne jo subdomeną."
            "Be to, domenas nėra įtrauktas į Viešojo Sufikso Sąrašą (https://publicsuffix.org/) - prašome patikrinti, ar tai teisinga.",
        ),
        ("Please provide a correct domain name.", "Prašome pateikti teisingą domeno pavadinimą."),
        (
            f"Failed to retrieve MX records for the domain of {PLACEHOLDER} email address {PLACEHOLDER} - All nameservers failed to answer the query {PLACEHOLDER}",
            f"Nepavyko gauti MX įrašų domenui, susijusiam su el. pašto adresu {PLACEHOLDER}: {PLACEHOLDER} - Visi serveriai, "
            f"kuriems užklausa {PLACEHOLDER}, neatsakė teisingai.",
        ),
        (
            f"All nameservers failed to answer the query {PLACEHOLDER}. IN {PLACEHOLDER}",
            f"Visi domeno serveriai neatsakė į užklausą dėl domeno {PLACEHOLDER}. IN {PLACEHOLDER}.",
        ),
        (
            f"{PLACEHOLDER}: Expected {PLACEHOLDER} at position {PLACEHOLDER} (marked with {PLACEHOLDER}) in: {PLACEHOLDER}",
            f"{SKIP_PLACEHOLDER}{SKIP_PLACEHOLDER}Įrašas neturi teisingos sintaksės. Klaida yra tikėtina pozicijoje {PLACEHOLDER} (pažymėtoje simboliu {PLACEHOLDER}) įraše '{PLACEHOLDER}'.",
        ),
        ("the p tag must immediately follow the v tag", "p žyma turi nedelsiant sekti po v žymos."),
        ('The record is missing the required policy ("p") tag', 'Įrašas neturi būtinosios politikos ("p") žymos.'),
        (
            f"{PLACEHOLDER} is not a valid ipv4 value{PLACEHOLDER}",
            f"{PLACEHOLDER} nėra galiojantis ipv4 adreso reikšmė.",
        ),
        (
            f"{PLACEHOLDER} is not a valid ipv6 value{PLACEHOLDER}",
            f"{PLACEHOLDER} nėra galiojantis ipv6 adreso reikšmė.",
        ),
        (
            "Some DMARC reporters might not send to more than two rua URIs",
            "Kai kurios DMARC ataskaitos gali neatsiųsti į daugiau nei dvi rua URIs.",
        ),
        (
            "Some DMARC reporters might not send to more than two ruf URIs",
            "Kai kurios DMARC ataskaitos gali neatsiųsti į daugiau nei dvi ruf URIs.",
        ),
        (f"The domain {PLACEHOLDER} does not exist", f"Domenas {PLACEHOLDER} neegzistuoja."),
        (
            f"{PLACEHOLDER} is not a valid DMARC report URI - please make sure that the URI begins with a schema such as mailto:",
            f"{PLACEHOLDER} nėra galiojantis DMARC ataskaitos URI - prašome užtikrinti, kad URI prasideda schemomis, tokiais kaip mailto:",
        ),
        (f"{PLACEHOLDER} is not a valid DMARC report URI", f"{PLACEHOLDER} nėra galiojantis DMARC ataskaitos URI."),
        (f"{PLACEHOLDER} is not a valid DMARC tag", f"'{PLACEHOLDER}' nėra galiojančios DMARC žymės."),
        (
            f"Tag {PLACEHOLDER} must have one of the following values: {PLACEHOLDER} - not {PLACEHOLDER}",
            f"Žyma {PLACEHOLDER} turi turėti vieną iš šių reikšmių: {PLACEHOLDER} - o ne {PLACEHOLDER}.",
        ),
        (
            "pct value is less than 100. This leads to inconsistent and unpredictable policy "
            "enforcement. Consider using p=none to monitor results instead",
            "pct reikšmė yra mažesnė nei 100. Tai lemia nenuoseklų ir neprognozuojamą politikos "
            "įgyvendinimą. Svarstykite naudoti p=none, kad stebėti rezultatus.",
        ),
        ("pct value must be an integer between 0 and 100", "pct reikšmė turi būti sveikasis skaičius nuo 0 iki 100."),
        (f"Duplicate include: {PLACEHOLDER}", f"Pakartotas įtraukimas: {PLACEHOLDER}."),
        (
            "When 1 is present in the fo tag, including 0 is redundant",
            "Kai fo žymėje yra 1, įtraukti 0 yra nereikalinga.",
        ),
        ("Including 0 and 1 fo tag values is redundant", "reikšmė 0 ir 1  yra pertekliniai fo tag'e."),
        (
            f"{PLACEHOLDER} is not a valid option for the DMARC {PLACEHOLDER} tag",
            f"'{PLACEHOLDER}' nėra galiojanti parinktis DMARC {PLACEHOLDER} žymėje.",
        ),
        (
            f"Domain checked by the SPF mechanism (from the RFC5321.MailFrom header: {PLACEHOLDER}) is not aligned with "
            f"the DMARC record domain (from the RFC5322.From header: {PLACEHOLDER}). Read more about various e-mail From "
            f"headers on https://dmarc.org/2016/07/how-many-from-addresses-are-there/",
            f"SPF mechanizmo tikrinama domena (iš RFC5321.MailFrom antraštės: {PLACEHOLDER}) neatitinka "
            f"DMARC įrašo domenos (iš RFC5322.From antraštės: {PLACEHOLDER}). Daugiau informacijos apie įvairias siuntėjo "
            f"el. pašto antraštes galite rasti adresu https://dmarc.org/2016/07/how-many-from-addresses-are-there/.",
        ),
        (
            f"Domain from the DKIM signature ({PLACEHOLDER}) is not aligned with the DMARC record domain "
            f"(from the From header: {PLACEHOLDER}).",
            f"DKIM parašo domena ({PLACEHOLDER}) neatitinka DMARC įrašo domenos "
            f"(iš From antraštės: {PLACEHOLDER}).",
        ),
        (
            "Invalid or no e-mail domain in the message From header",
            "Neteisinga arba nėra el. pašto domeno laiško Siuntėjo antraštėje.",
        ),
        (
            "A DNS name is > 255 octets long.",
            "DNS pavadinimas yra ilgesnis nei 255 oktetai.",
        ),
        (
            "The value of the pct tag must be an integer",
            "pct žymės reikšmė turi būti sveikasis skaičius.",
        ),
        (
            f"The domain for rua email address {PLACEHOLDER} has no MX records",
            f"rua el. pašto adreso domenas {PLACEHOLDER} neturi MX įrašų.",
        ),
        (
            f"The domain for ruf email address {PLACEHOLDER} has no MX records",
            f"ruf el. pašto adreso domenas {PLACEHOLDER} neturi MX įrašų.",
        ),
        (
            f"Failed to retrieve MX records for the domain of {PLACEHOLDER} email address {PLACEHOLDER} - The domain {PLACEHOLDER} does not exist",
            f"Nepavyko gauti MX įrašų domenui, susijusiai su el. pašto adresu {PLACEHOLDER}: {PLACEHOLDER} - Domenas {PLACEHOLDER} neegzistuoja.",
        ),
        (
            "An unknown error has occured during configuration validation.",
            "Konfigūracijos patvirtinimo metu įvyko nežinoma klaida.",
        ),
        # dkimpy messages
        (
            f"{PLACEHOLDER} value is not valid base64 {PLACEHOLDER}",
            f"{PLACEHOLDER} reikšmė nėra galiojantis base64 {PLACEHOLDER}",
        ),
        (f"{PLACEHOLDER} value is not valid {PLACEHOLDER}", f"{PLACEHOLDER} reikšmė nėra galiojanti {PLACEHOLDER}"),
        (f"missing {PLACEHOLDER}", f"trūksta {PLACEHOLDER}"),
        (
            f"unknown signature algorithm: {PLACEHOLDER}",
            f"Nežinomas parašo algoritmas: {PLACEHOLDER}",
        ),
        (
            f"i= domain is not a subdomain of d= {PLACEHOLDER}",
            f"Domenas i= nėra subdomenas d= {PLACEHOLDER}",
        ),
        (
            f"{PLACEHOLDER} value is not a decimal integer {PLACEHOLDER}",
            f"{PLACEHOLDER} reikšmė nėra dešimtainis skaičius {PLACEHOLDER}",
        ),
        (
            f"q= value is not dns/txt {PLACEHOLDER}",
            f"q= reikšmė nėra dns/txt {PLACEHOLDER}",
        ),
        (
            f"v= value is not 1 {PLACEHOLDER}",
            f"v= reikšmė nėra 1 {PLACEHOLDER}",
        ),
        (
            f"t= value is in the future {PLACEHOLDER}",
            f"t= reikšmė yra ateityje {PLACEHOLDER}",
        ),
        (
            f"x= value is past {PLACEHOLDER}",
            f"x= reikšmė yra praeityje {PLACEHOLDER}",
        ),
        (
            f"x= value is less than t= value {PLACEHOLDER}",
            f"x= reikšmė yra mažesnė nei t= reikšmė {PLACEHOLDER}",
        ),
        (
            f"Unexpected characters in RFC822 header: {PLACEHOLDER}",
            f"Netikėti simboliai RFC822 antraštėje: {PLACEHOLDER}",
        ),
        (
            f"missing public key: {PLACEHOLDER}",
            f"Trūksta viešojo rakto: {PLACEHOLDER}",
        ),
        (
            "bad version",
            "Netinkama versija",
        ),
        (
            f"could not parse ed25519 public key {PLACEHOLDER}",
            f"Nepavyko analizuoti ed25519 viešojo rakto {PLACEHOLDER}",
        ),
        (
            f"incomplete RSA public key: {PLACEHOLDER}",
            f"Neužbaigtas RSA viešasis raktas: {PLACEHOLDER}",
        ),
        (
            f"could not parse RSA public key {PLACEHOLDER}",
            f"Nepavyko analizuoti RSA viešojo rakto {PLACEHOLDER}",
        ),
        (
            f"unknown algorithm in k= tag: {PLACEHOLDER}",
            f"Nežinomas algoritmas k= žymėje: {PLACEHOLDER}",
        ),
        (
            f"unknown service type in s= tag: {PLACEHOLDER}",
            f"Nežinomas paslaugos tipas s= žymėje: {PLACEHOLDER}",
        ),
        (
            "digest too large for modulus",
            "Pasirašytas tekstas per didelis moduliui",
        ),
        (
            f"digest too large for modulus: {PLACEHOLDER}",
            f"Hash per didelis moduliui: {PLACEHOLDER}",
        ),
        (
            f"body hash mismatch (got b'{PLACEHOLDER}', expected b'{PLACEHOLDER}')",
            f"body hash nesuderinamumas (gauta b'{PLACEHOLDER}', tikimasi b'{PLACEHOLDER}')",
        ),
        (
            f"public key too small: {PLACEHOLDER}",
            f"Viešas raktas per mažas: {PLACEHOLDER}",
        ),
        (
            f"Duplicate ARC-Authentication-Results for instance {PLACEHOLDER}",
            f"Kartotinos ARC-Authentication-Results {PLACEHOLDER} atveju",
        ),
        (
            f"Duplicate ARC-Message-Signature for instance {PLACEHOLDER}",
            f"Kartotinos ARC-Message-Signature {PLACEHOLDER} atveju",
        ),
        (
            f"Duplicate ARC-Seal for instance {PLACEHOLDER}",
            f"Kartotinos ARC-Seal {PLACEHOLDER} atveju",
        ),
        (
            f"Incomplete ARC set for instance {PLACEHOLDER}",
            f"Neužbaigtas ARC rinkinys {PLACEHOLDER} atveju",
        ),
        (
            "h= tag not permitted in ARC-Seal header field",
            "h= žymė neleidžiama ARC-Seal antraštėje",
        ),
        (
            "An unknown error occured during DKIM signature validation.",
            "DKIM parašo patvirtinimo metu įvyko nežinoma klaida.",
        ),
    ],
    Language.pl_PL: [  # type: ignore
        (
            "SPF '~all' or '-all' directive not found. We recommend adding it, as it describes "
            "what should happen with messages that fail SPF verification. For example, "
            "'-all' will tell the recipient server to drop such messages.",
            "Nie znaleziono dyrektywy '~all' lub '-all' w rekordzie SPF. Rekomendujemy jej dodanie, ponieważ "
            "opisuje ona, jak powinny zostać potraktowane wiadomości, które zostaną odrzucone "
            "przez mechanizm SPF. Na przykład, dyrektywa '-all' wskazuje serwerowi odbiorcy, "
            "że powinien odrzucać takie wiadomości.",
        ),
        (
            "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
            "Nie znaleziono poprawnego rekordu SPF. Rekomendujemy używanie wszystkich trzech mechanizmów: "
            "SPF, DKIM i DMARC, aby zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana "
            "przez serwer odbiorcy.",
        ),
        (
            "Multiple SPF records found. We recommend leaving only one, as multiple SPF records "
            "can cause problems with some SPF implementations.",
            "Wykryto więcej niż jeden rekord SPF. Rekomendujemy pozostawienie jednego z nich - "
            "obecność wielu rekordów może powodować problemy w działaniu niektórych implementacji mechanizmu SPF.",
        ),
        (
            f"The SPF record's include chain has a reference to the {PLACEHOLDER} domain that doesn't "
            "have an SPF record. When using directives such as 'include' or 'redirect' remember "
            "that the destination domain must have a correct SPF record.",
            f"Rekord SPF odwołuje się (być może pośrednio) do domeny {PLACEHOLDER}, która nie zawiera rekordu SPF. "
            "W przypadku odwoływania się do innych domen za pomocą dyrektyw SPF takich jak 'include' lub 'redirect', "
            "domena docelowa powinna również zawierać rekord SPF.",
        ),
        (
            "SPF record causes too many void DNS lookups. Some implementations may require the number of "
            "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
            "are caused by directives such as 'mx' or 'include'.",
            "Rekord SPF powoduje zbyt wiele nieudanych zapytań DNS. Niektóre implementacje mechanizmu "
            "SPF wymagają, aby liczba nieudanych zapytań DNS (np. odwołujących się do nieistniejących domen) była "
            "niska. Takie zapytania DNS mogą być spowodowane np. przez dyrektywy SPF 'mx' czy 'include'.",
        ),
        (
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain.",
            "Rekord SPF zawiera nieskończoną pętlę. Prosimy sprawdzić, czy dyrektywy SPF 'include' lub 'redirect' "
            "nie odwołują się z powrotem do tej samej domeny lub do wcześniejszych domen.",
        ),
        (
            "SPF record causes too many DNS lookups. The DNS lookups are caused by directives such as 'mx' or 'include'. "
            "The specification requires the number of DNS lookups to be lower or equal to 10 to decrease load on DNS servers.",
            "Rekord SPF powoduje zbyt wiele zapytań DNS. Zapytania DNS są powodowane przez niektóre dyrektywy SPF, takie jak "
            "'mx' czy 'include'. Specyfikacja wymaga, aby liczba zapytań DNS nie przekraczała 10, aby nie powodować nadmiernego "
            "obciążenia serwerów DNS.",
        ),
        (
            "The ptr mechanism should not be used - https://tools.ietf.org/html/rfc7208#section-5.5",
            "Zgodnie ze specyfikacją SPF, nie należy używać mechanizmu 'ptr'. Pod adresem "
            "https://tools.ietf.org/html/rfc7208#section-5.5 można znaleźć uzasadnienie tej rekomendacji.",
        ),
        (
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
            "Nie znaleziono poprawnego rekordu DMARC. Rekomendujemy używanie wszystkich trzech mechanizmów: "
            "SPF, DKIM i DMARC, aby zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana "
            "przez serwer odbiorcy.",
        ),
        (
            "DMARC policy is 'none' and 'rua' is not set, which means that the DMARC setting is not effective.",
            "Polityka DMARC jest ustawiona na 'none' i nie ustawiono odbiorcy raportów w polu 'rua', co "
            "oznacza, że ustawienie DMARC nie będzie skuteczne.",
        ),
        (
            f"The DMARC record must be located at {PLACEHOLDER}, not {PLACEHOLDER}",
            f"Rekord DMARC powinien znajdować się w domenie {PLACEHOLDER}, nie {PLACEHOLDER}.",
        ),
        (
            "There are multiple DMARC records. We recommend leaving only one, as multiple "
            "DMARC records can cause problems with some DMARC implementations.",
            "Wykryto więcej niż jeden rekord DMARC. Rekomendujemy pozostawienie jednego z nich - "
            "obecność wielu rekordów może powodować problemy w działaniu niektórych implementacji "
            "mechanizmu DMARC.",
        ),
        (
            "There is an SPF record instead of DMARC one on the '_dmarc' subdomain.",
            "Zamiast rekordu DMARC wykryto rekord SPF w subdomenie '_dmarc'.",
        ),
        (
            f"Failed to retrieve MX records for the domain of rua email address {PLACEHOLDER} - "
            f"The resolution lifetime expired {PLACEHOLDER}",
            f"Nie udało się pobrać rekordów MX domeny adresu e-mail podanego w rekordzie 'rua': {PLACEHOLDER} - "
            "przekroczono limit czasu żądania.",
        ),
        (
            "DMARC record uses an invalid tag. Please refer to https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 "
            "for the list of available tags.",
            "Rekord DMARC zawiera niepoprawne pole. Pod adresem "
            "https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci/#dmarc-pola "
            "znajdziesz opis przykładowych pól, które mogą znaleźć się w takim rekordzie, a w specyfikacji mechanizmu "
            "DMARC pod adresem https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 - opis wszystkich pól.",
        ),
        (
            "DMARC report URI is invalid. The report URI should be an e-mail address prefixed with mailto:.",
            "Adres raportów DMARC jest niepoprawny. Powinien to być adres e-mail rozpoczynający się od mailto:.",
        ),
        (
            "The destination of a DMARC report URI does not indicate that it accepts reports for the domain.",
            "Adres raportów DMARC nie wskazuje, że przyjmuje raporty z tej domeny.",
        ),
        (
            "Subdomain policy (sp=) should be reject for parked domains",
            "Polityka subdomen (sp=) powinna być ustawiona na 'reject' dla domen "
            "niesłużących do wysyłki poczty - serwer odbiorcy powinien odrzucać wiadomości z takich domen.",
        ),
        (
            "Policy (p=) should be reject for parked domains",
            "Polityka (p=) powinna być ustawiona na 'reject' dla domen niesłużących "
            "do wysyłki poczty - serwer odbiorcy powinien odrzucać wiadomości z takich domen.",
        ),
        (
            "Unrelated TXT record found in the '_dmarc' subdomain. We recommend removing it, as such unrelated "
            "records may cause problems with some DMARC implementations.",
            "Znaleziono niepowiązane rekordy TXT w subdomenie '_dmarc'. Rekomendujemy ich usunięcie, ponieważ "
            "niektóre serwery mogą w takiej sytuacji odrzucić konfigurację DMARC jako błędną.",
        ),
        (
            "Unrelated TXT record found in the '_dmarc' subdomain of a domain the record refers to. "
            "We recommend removing it, as such unrelated records may cause problems with some DMARC "
            "implementations.",
            "Znaleziono niepowiązane rekordy TXT w subdomenie '_dmarc' domeny, do której odwołuje się rekord. "
            "Rekomendujemy ich usunięcie, ponieważ niektóre serwery mogą w takiej sytuacji odrzucić "
            "konfigurację DMARC jako błędną.",
        ),
        (
            "The domain of the email address in a DMARC report URI is missing MX records. That means, that this domain "
            "may not receive DMARC reports.",
            "Domena adresu e-mail w adresie raportów DMARC nie zawiera rekordów MX. Oznacza to, że raporty DMARC mogą nie być "
            "poprawnie dostarczane.",
        ),
        (
            "DMARC policy is 'none', which means that besides reporting no action will be taken. The policy describes what "
            "action the recipient server should take when noticing a message that doesn't pass the verification. 'quarantine' policy "
            "suggests the recipient server to flag the message as spam and 'reject' policy suggests the recipient "
            "server to reject the message. We recommend using the 'quarantine' or 'reject' policy.\n\n"
            "When testing the DMARC mechanism, to minimize the risk of correct messages not being delivered, "
            "the 'none' policy may be used. Such tests are recommended especially when the domain is used to "
            "send a large number of e-mails using various tools and not delivering a correct message is "
            "unacceptable. In such cases the reports should be closely monitored, and the target setting should "
            "be 'quarantine' or 'reject'.",
            "Polityka DMARC jest ustawiona na 'none', co oznacza, że oprócz raportowania, żadna dodatkowa akcja nie zostanie "
            "wykonana. Polityka DMARC opisuje serwerowi odbiorcy, jaką akcję powinien podjąć, gdy wiadomość nie zostanie "
            "poprawnie zweryfikowana. Polityka 'quarantine' oznacza, że taka wiadomość powinna zostać oznaczona jako spam, a polityka 'reject' - że "
            "powinna zostać odrzucona przez serwer odbiorcy. Rekomendujemy korzystanie z polityki 'quarantine' lub 'reject'.\n\n"
            "W trakcie testów działania mechanizmu DMARC, w celu zmniejszenia ryzyka, że poprawne wiadomości zostaną "
            "odrzucone, może być tymczasowo stosowane ustawienie 'none'. Takie testy są szczególnie zalecane, jeśli "
            "domena służy do wysyłki dużej liczby wiadomości przy użyciu różnych narzędzi, a potencjalne niedostarczenie "
            "poprawnej wiadomości jest niedopuszczalne. W takich sytuacjach raporty powinny być dokładnie monitorowane, "
            "a docelowym ustawieniem powinno być 'quarantine' lub 'reject'.",
        ),
        (
            "rua tag (destination for aggregate reports) not found",
            "Nie znaleziono tagu 'rua' (odbiorca zagregowanych raportów).",
        ),
        (
            "Whitespace in domain name detected. Please provide a correct domain name.",
            "Wykryto białe znaki w nazwie domeny. Prosimy o podanie poprawnej nazwy domeny.",
        ),
        (
            f"Unexpected character in domain detected: {PLACEHOLDER}. Please provide a correct domain name.",
            f"Wykryto błędne znaki w nazwie domeny: {PLACEHOLDER}. Prosimy o podanie poprawnej nazwy domeny.",
        ),
        (
            "Any text after the all mechanism is ignored",
            "Tekst umieszczony po dyrektywie 'all' zostanie zignorowany. Rekomendujemy jego usunięcie, lub, "
            "jeśli jest niezbędnym elementem konfiguracji, umieszczenie przed dyrektywą 'all' rekordu SPF.",
        ),
        (
            "No DKIM signature found",
            "Nie znaleziono podpisu DKIM. Rekomendujemy używanie wszystkich trzech mechanizmów: SPF, DKIM i DMARC, aby "
            "zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana przez serwer odbiorcy.",
        ),
        (
            "Found an invalid DKIM signature",
            "Znaleziono niepoprawny podpis mechanizmu DKIM.",
        ),
        (
            "SPF records containing macros aren't supported by the system yet.",
            "Rekordy SPF zawierające makra nie są jeszcze wspierane przez serwis.",
        ),
        (
            f"The resolution lifetime expired after {PLACEHOLDER}",
            "Przekroczono czas oczekiwania na odpowiedź serwera DNS. Prosimy spróbować jeszcze raz.",
        ),
        (
            f"DMARC record at root of {PLACEHOLDER} has no effect",
            f"Rekord DMARC w domenie '{PLACEHOLDER}' (zamiast w subdomenie '_dmarc') nie zostanie uwzględniony.",
        ),
        (
            "Found a DMARC record that starts with whitespace. Please remove the whitespace, as some "
            "implementations may not process it correctly.",
            "Wykryto rekord DMARC zaczynający się od spacji lub innych białych znaków. Rekomendujemy ich "
            "usunięcie, ponieważ niektóre serwery pocztowe mogą nie zinterpretować takiego rekordu poprawnie.",
        ),
        (
            f"{PLACEHOLDER} does not have any MX records",
            f"Rekord SPF w domenie {PLACEHOLDER} korzysta z dyrektywy SPF 'mx', lecz nie wykryto rekordów MX, w związku "
            "z czym ta dyrektywa nie zadziała poprawnie.",
        ),
        (
            f"{PLACEHOLDER} does not have any A/AAAA records",
            f"Rekord SPF w domenie {PLACEHOLDER} korzysta z dyrektywy SPF 'a', lecz nie wykryto rekordów A/AAAA, w związku "
            "z czym ta dyrektywa nie zadziała poprawnie.",
        ),
        (
            f"{PLACEHOLDER} does not indicate that it accepts DMARC reports about {PLACEHOLDER} - Authorization record not found: {PLACEHOLDER}",
            f"Domena {PLACEHOLDER} nie wskazuje, że przyjmuje raporty DMARC na temat domeny {PLACEHOLDER} - nie wykryto rekordu autoryzacyjnego. "
            "Więcej informacji na temat rekordów autoryzacyjnych, czyli rekordów służących do zezwolenia na wysyłanie raportów DMARC do innej "
            "domeny, można przeczytać pod adresem https://dmarc.org/2015/08/receiving-dmarc-reports-outside-your-domain/ .",
        ),
        (
            "SPF type DNS records found. Use of DNS Type SPF has been removed in the standards track version of SPF, RFC 7208. These records "
            f"should be removed and replaced with TXT records: {PLACEHOLDER}",
            "Wykryto rekordy DNS o typie SPF. Wykorzystanie rekordów tego typu zostało usunięte ze standardu – powinny zostać zastąpione rekordami "
            "TXT. Obecność rekordów SPF nie stanowi wprost zagrożenia (jeśli obecne są również poprawne rekordy TXT), ale może prowadzić do pomyłek "
            "(np. w sytuacji, gdy administrator wyedytuje tylko jeden z rekordów).",
        ),
        (
            "Requested to scan a domain that is a public suffix, i.e. a domain such as .com where anybody could "
            "register their subdomain. Such domain don't have to have properly configured e-mail sender verification "
            "mechanisms. Please make sure you really wanted to check such domain and not its subdomain.",
            "Sprawdzają Państwo domenę z listy Public Suffix List (https://publicsuffix.org/) czyli taką jak .pl, gdzie  "
            "różne podmioty mogą zarejestrować swoje subdomeny. Takie domeny nie muszą mieć skonfigurowanych mechanizmów "
            "weryfikacji nadawcy poczty - konfigurowane są one w subdomenach. Prosimy o weryfikację nazwy sprawdzanej domeny.",
        ),
        (
            "Requested to scan a top-level domain. Top-level domains don't have to have properly configured e-mail sender "
            "verification mechanisms. Please make sure you really wanted to check such domain and not its subdomain."
            "Besides, the domain is not known to the Public Suffix List (https://publicsuffix.org/) - please verify whether "
            "it is correct.",
            "Sprawdzają Państwo domenę najwyższego poziomu. Domeny najwyższego poziomu nie muszą mieć "
            "skonfigurowanych mechanizmów weryfikacji nadawcy poczty - konfigurowane są one w subdomenach. Prosimy "
            "o weryfikację nazwy sprawdzanej domeny. Domena nie występuje również na Public Suffix List "
            "(https://publicsuffix.org/) - prosimy o weryfikację jej poprawności.",
        ),
        (
            "Please provide a correct domain name.",
            "Proszę podać poprawną nazwę domeny.",
        ),
        (
            f"Failed to retrieve MX records for the domain of {PLACEHOLDER} email address {PLACEHOLDER} - All nameservers failed to answer the query {PLACEHOLDER}",
            f"Nie udało się odczytać rekordów MX domeny adresu e-mail w dyrektywie {PLACEHOLDER}: {PLACEHOLDER} - serwery nazw nie odpowiedziały poprawnie na zapytanie.",
        ),
        (
            f"All nameservers failed to answer the query {PLACEHOLDER}. IN {PLACEHOLDER}",
            f"Żaden z przypisanych serwerów nazw domen nie odpowiedział na zapytanie dotyczące domeny {PLACEHOLDER}.",
        ),
        (
            f"{PLACEHOLDER}: Expected {PLACEHOLDER} at position {PLACEHOLDER} (marked with {PLACEHOLDER}) in: {PLACEHOLDER}",
            f"{SKIP_PLACEHOLDER}{SKIP_PLACEHOLDER}Rekord nie ma poprawnej składni. Błąd występuje na przybliżonej pozycji "
            f"{PLACEHOLDER} (oznaczonej znakiem {PLACEHOLDER}) w rekordzie '{PLACEHOLDER}'",
        ),
        (
            "the p tag must immediately follow the v tag",
            "Tag p (polityka DMARC) musi następować bezpośrednio po tagu v (wersji DMARC).",
        ),
        (
            'The record is missing the required policy ("p") tag',
            "Rekord nie zawiera tagu p, opisującego politykę - czyli akcję, która powinna zostać wykonana, gdy wiadomość nie "
            "zostanie zweryfikowana poprawnie przy użyciu mechanizmu DMARC.",
        ),
        (
            f"{PLACEHOLDER} is not a valid ipv4 value{PLACEHOLDER}",
            f"{PLACEHOLDER} nie jest poprawnym adresem IPv4.",
        ),
        (
            f"{PLACEHOLDER} is not a valid ipv6 value{PLACEHOLDER}",
            f"{PLACEHOLDER} nie jest poprawnym adresem IPv6.",
        ),
        (
            "Some DMARC reporters might not send to more than two rua URIs",
            "Niektóre implementacje DMARC mogą nie wysłać raportów do więcej niż dwóch odbiorców podanych w polu 'rua'.",
        ),
        (
            "Some DMARC reporters might not send to more than two ruf URIs",
            "Niektóre implementacje DMARC mogą nie wysłać raportów do więcej niż dwóch odbiorców podanych w polu 'ruf'.",
        ),
        (
            f"The domain {PLACEHOLDER} does not exist",
            f"Domena {PLACEHOLDER} nie istnieje.",
        ),
        (
            f"{PLACEHOLDER} is not a valid DMARC report URI - please make sure that the URI begins with a schema such as mailto:",
            f"{PLACEHOLDER} nie jest poprawnym odbiorcą raportów DMARC - jeśli raporty DMARC mają być przesyłane na adres e-mail, "
            "należy poprzedzić go przedrostkiem 'mailto:'.",
        ),
        (
            f"{PLACEHOLDER} is not a valid DMARC report URI",
            f"{PLACEHOLDER} nie jest poprawnym odbiorcą raportów DMARC.",
        ),
        (
            f"{PLACEHOLDER} is not a valid DMARC tag",
            f"'{PLACEHOLDER}' nie jest poprawnym tagiem DMARC.",
        ),
        (
            f"Tag {PLACEHOLDER} must have one of the following values: {PLACEHOLDER} - not {PLACEHOLDER}",
            f"Tag {PLACEHOLDER} powinien mieć wartość spośród: {PLACEHOLDER} - wartość '{PLACEHOLDER}' nie jest dopuszczalna.",
        ),
        (
            "pct value is less than 100. This leads to inconsistent and unpredictable policy "
            "enforcement. Consider using p=none to monitor results instead",
            "Wartość tagu 'pct' wynosi mniej niż 100. Oznacza to, ze mechanizm DMARC zostanie "
            "zastosowany do mniej niż 100% wiadomości, a więc konfiguracja nie będzie spójnie "
            "egzekwowana. W celu monitorowania konfiguracji DMARC przed jej finalnym wdrożeniem "
            "rekomendujemy użycie polityki 'none' i monitorowanie przychodzących raportów DMARC.",
        ),
        (
            "pct value must be an integer between 0 and 100",
            "Wartość 'pct' (procent e-maili, do których zostanie zastosowana polityka DMARC) powinna "
            "być liczbą całkowitą od 0 do 100.",
        ),
        (
            f"Duplicate include: {PLACEHOLDER}",
            f"Domena {PLACEHOLDER} występuje wielokrotnie w tagu 'include'.",
        ),
        (
            "When 1 is present in the fo tag, including 0 is redundant",
            "Jeśli w tagu 'fo' (określającym, kiedy wysyłać raport DMARC) jest włączona opcja 1 (oznaczająca, że raport jest "
            "wysyłany jeśli wiadomość nie jest poprawnie zweryfikowana przez mechanizm SPF lub DKIM, nawet, jeśli "
            "została zweryfikowana przez drugi z mechanizmów), opcja 0 (tj. wysyłka raportów, gdy wiadomość zostanie "
            "zweryfikowana negatywnie przez oba mechanizmy) jest zbędna.",
        ),
        (
            "Including 0 and 1 fo tag values is redundant",
            "Jeśli w tagu 'fo' (określającym, kiedy wysyłać raport DMARC) jest włączona opcja 1 (oznaczająca, że raport jest "
            "wysyłany jeśli wiadomość nie jest poprawnie zweryfikowana przez mechanizm SPF lub DKIM, nawet, jeśli "
            "została zweryfikowana przez drugi z mechanizmów), opcja 0 (tj. wysyłka raportów, gdy wiadomość zostanie "
            "zweryfikowana negatywnie przez oba mechanizmy) jest zbędna.",
        ),
        (
            f"{PLACEHOLDER} is not a valid option for the DMARC {PLACEHOLDER} tag",
            f"'{PLACEHOLDER}' nie jest poprawną opcją tagu '{PLACEHOLDER}'",
        ),
        (
            f"Domain checked by the SPF mechanism (from the RFC5321.MailFrom header: {PLACEHOLDER}) is not aligned with "
            f"the DMARC record domain (from the RFC5322.From header: {PLACEHOLDER}). Read more about various e-mail From "
            f"headers on https://dmarc.org/2016/07/how-many-from-addresses-are-there/",
            f"Domena sprawdzana przez mechanizm SPF (z nagłówka RFC5321.MailFrom: {PLACEHOLDER}) nie jest zgodna z domeną "
            f"rekordu DMARC (z nagłówka RFC5322.From: {PLACEHOLDER}). Na stronie "
            f"https://dmarc.org/2016/07/how-many-from-addresses-are-there/ można przeczytać więcej o nagłówkach nadawcy wiadomości.",
        ),
        (
            f"Domain from the DKIM signature ({PLACEHOLDER}) is not aligned with the DMARC record domain "
            f"(from the From header: {PLACEHOLDER}).",
            f"Domena podpisu DKIM ({PLACEHOLDER}) nie jest zgodna z domeną rekordu "
            f"DMARC (z nagłówka From: {PLACEHOLDER}).",
        ),
        (
            "Invalid or no e-mail domain in the message From header",
            "Brak lub niepoprawna domena w nagłówku From e-maila.",
        ),
        (
            "A DNS name is > 255 octets long.",
            "Nazwa DNS ma więcej niż 255 bajtów.",
        ),
        (
            "The value of the pct tag must be an integer",
            "Wartość tagu 'pct' musi być liczbą całkowitą.",
        ),
        (
            f"The domain for rua email address {PLACEHOLDER} has no MX records",
            f"Domena adresu e-mail podanego w tagu 'rua': {PLACEHOLDER} nie ma rekordów MX.",
        ),
        (
            f"The domain for ruf email address {PLACEHOLDER} has no MX records",
            f"Domena adresu e-mail podanego w tagu 'ruf': {PLACEHOLDER} nie ma rekordów MX.",
        ),
        (
            f"Failed to retrieve MX records for the domain of {PLACEHOLDER} email address {PLACEHOLDER} - The domain {PLACEHOLDER} does not exist",
            f"Nie udało się pobrać rekordów MX domeny adresu e-mail podanego w tagu '{PLACEHOLDER}': {PLACEHOLDER} - domena {PLACEHOLDER} nie istnieje.",
        ),
        (
            "An unknown error has occured during configuration validation.",
            "Wystąpił nieznany błąd podczas sprawdzania konfiguracji.",
        ),
        # dkimpy messages
        (
            f"{PLACEHOLDER} value is not valid base64 {PLACEHOLDER}",
            f"Wartość {PLACEHOLDER} nie jest poprawnie zakodowana algorytmem base64 {PLACEHOLDER}",
        ),
        (
            f"{PLACEHOLDER} value is not valid {PLACEHOLDER}",
            f"Wartość {PLACEHOLDER} nie jest poprawna {PLACEHOLDER}",
        ),
        (
            f"missing {PLACEHOLDER}",
            f"Brakujące pole {PLACEHOLDER}",
        ),
        (
            f"unknown signature algorithm: {PLACEHOLDER}",
            f"Nieznany algorytm podpisu DKIM: {PLACEHOLDER}",
        ),
        (
            f"i= domain is not a subdomain of d= {PLACEHOLDER}",
            f"Domena w polu i= nie jest subdomeną domeny w polu d= {PLACEHOLDER}",
        ),
        (
            f"{PLACEHOLDER} value is not a decimal integer {PLACEHOLDER}",
            f"Wartość w polu {PLACEHOLDER} nie jest liczbą {PLACEHOLDER}",
        ),
        (
            f"q= value is not dns/txt {PLACEHOLDER}",
            f"Wartość w polu q= nie jest równa 'dns/txt' {PLACEHOLDER}",
        ),
        (
            f"v= value is not 1 {PLACEHOLDER}",
            f"Wartość w polu v= nie jest równa 1 {PLACEHOLDER}",
        ),
        (
            f"t= value is in the future {PLACEHOLDER}",
            f"Czas w polu t= jest w przyszłości {PLACEHOLDER}",
        ),
        (
            f"x= value is past {PLACEHOLDER}",
            f"Czas w polu x= jest w przeszłości {PLACEHOLDER}",
        ),
        (
            f"x= value is less than t= value {PLACEHOLDER}",
            f"Czas w polu x= jest wcześniejszy niż w polu t= {PLACEHOLDER}",
        ),
        (
            f"Unexpected characters in RFC822 header: {PLACEHOLDER}",
            f"Nieoczekiwane znaki w nagłówku RFC822: {PLACEHOLDER}",
        ),
        (
            f"missing public key: {PLACEHOLDER}",
            f"Brakujący klucz publiczny: {PLACEHOLDER}",
        ),
        (
            "bad version",
            "Niepoprawna wersja",
        ),
        (
            f"could not parse ed25519 public key {PLACEHOLDER}",
            f"Nie udało się przetworzyć klucza publicznego ed25519 {PLACEHOLDER}",
        ),
        (
            f"incomplete RSA public key: {PLACEHOLDER}",
            f"Niekompletny klucz publiczny RSA: {PLACEHOLDER}",
        ),
        (
            f"could not parse RSA public key {PLACEHOLDER}",
            f"Nie udało się przetworzyć klucza publicznego RSA {PLACEHOLDER}",
        ),
        (
            f"unknown algorithm in k= tag: {PLACEHOLDER}",
            f"Nieznana nazwa algorytmu w polu k=: {PLACEHOLDER}",
        ),
        (
            f"unknown service type in s= tag: {PLACEHOLDER}",
            f"Nieznany typ usługi w polu s=: {PLACEHOLDER}",
        ),
        (
            "digest too large for modulus",
            "Podpis jest dłuższy niż dopuszczają użyte parametry algorytmu szyfrującego.",
        ),
        (
            f"digest too large for modulus: {PLACEHOLDER}",
            f"Podpis jest dłuższy niż dopuszczają użyte parametry algorytmu szyfrującego: {PLACEHOLDER}.",
        ),
        (
            f"body hash mismatch (got b'{PLACEHOLDER}', expected b'{PLACEHOLDER}')",
            f"Niepoprawna suma kontrolna treści wiadomości (otrzymano '{PLACEHOLDER}', oczekiwano '{PLACEHOLDER}').",
        ),
        (
            f"public key too small: {PLACEHOLDER}",
            f"Za mały klucz publiczny: {PLACEHOLDER}.",
        ),
        (
            f"Duplicate ARC-Authentication-Results for instance {PLACEHOLDER}",
            f"Wykryto wiele nagłówków ARC-Authentication-Results dla instancji {PLACEHOLDER}.",
        ),
        (
            f"Duplicate ARC-Message-Signature for instance {PLACEHOLDER}",
            f"Wykryto wiele nagłówków ARC-Message-Signature dla instancji {PLACEHOLDER}.",
        ),
        (
            f"Duplicate ARC-Seal for instance {PLACEHOLDER}",
            f"Wykryto wiele nagłówków ARC-Seal dla instancji {PLACEHOLDER}.",
        ),
        (
            f"Incomplete ARC set for instance {PLACEHOLDER}",
            f"Niekompletny zestaw nagłówków ARC dla instancji {PLACEHOLDER}.",
        ),
        (
            "h= tag not permitted in ARC-Seal header field",
            "Tag h= nie jest dozwolony w nagłówku ARC-Seal.",
        ),
        (
            "An unknown error occured during DKIM signature validation.",
            "Wystąpił nieznany błąd podczas walidacji podpisu DKIM.",
        ),
    ],
}


def _translate_using_dictionary(
    message: str,
    dictionary: List[Tuple[str, str]],
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> str:
    """Translates message according to a dictionary.

    For example, for the following dictionary:

    [
        (f"Input message one {PLACEHOLDER}.", f"Output message one {PLACEHOLDER}."),
        (f"Input message two {PLACEHOLDER}.", f"Output message two {PLACEHOLDER}."),
    ]

    message "Input message one 1234." will get translated to "Output message one 1234.".

    *note* the "from" and "to" messages must have the same number of placeholders -
    and will have the same order of placeholders.
    """
    for m_from, m_to in dictionary:
        pattern = "^" + re.escape(m_from).replace(PLACEHOLDER, "((?:.|\n)*)") + "$"
        regexp_match = re.match(pattern, message)

        # a dictionary rule matched the message
        if regexp_match:
            result = m_to
            for matched in regexp_match.groups():
                placeholder_index = result.index(PLACEHOLDER) if PLACEHOLDER in result else len(result)
                skip_placeholder_index = result.index(SKIP_PLACEHOLDER) if SKIP_PLACEHOLDER in result else len(result)

                if placeholder_index < skip_placeholder_index:
                    # replace first occurence of placeholder with the matched needle
                    result = result.replace(PLACEHOLDER, matched, 1)
                elif skip_placeholder_index < placeholder_index:
                    result = result.replace(SKIP_PLACEHOLDER, "", 1)
            return result

    if nonexistent_translation_handler:
        return nonexistent_translation_handler(message)
    else:
        raise NotImplementedError(f"Unable to translate {message}")


def translate(
    message: str,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> str:
    if language == Language.en_US:  # type: ignore
        return message

    return _translate_using_dictionary(
        message,
        TRANSLATIONS[language],
        nonexistent_translation_handler=nonexistent_translation_handler,
    )


def _translate_domain_result(
    domain_result: DomainScanResult,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> DomainScanResult:
    new_domain_result = copy.deepcopy(domain_result)
    new_domain_result.spf.errors = [
        translate(error, language, nonexistent_translation_handler) for error in domain_result.spf.errors
    ]
    new_domain_result.spf.warnings = [
        translate(warning, language, nonexistent_translation_handler) for warning in domain_result.spf.warnings
    ]
    new_domain_result.dmarc.errors = [
        translate(error, language, nonexistent_translation_handler) for error in domain_result.dmarc.errors
    ]
    new_domain_result.dmarc.warnings = [
        translate(warning, language, nonexistent_translation_handler) for warning in domain_result.dmarc.warnings
    ]
    new_domain_result.warnings = [
        translate(warning, language, nonexistent_translation_handler) for warning in new_domain_result.warnings
    ]
    return new_domain_result


def _translate_dkim_result(
    dkim_result: DKIMScanResult,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> DKIMScanResult:
    new_dkim_result = copy.deepcopy(dkim_result)
    new_dkim_result.errors = [
        translate(error, language, nonexistent_translation_handler) for error in dkim_result.errors
    ]
    new_dkim_result.warnings = [
        translate(warning, language, nonexistent_translation_handler) for warning in dkim_result.warnings
    ]
    return new_dkim_result


def translate_scan_result(
    scan_result: ScanResult,
    language: Language,
    nonexistent_translation_handler: Optional[Callable[[str], str]] = None,
) -> ScanResult:
    return ScanResult(
        domain=(
            _translate_domain_result(scan_result.domain, language, nonexistent_translation_handler)
            if scan_result.domain
            else None
        ),
        dkim=(
            _translate_dkim_result(scan_result.dkim, language, nonexistent_translation_handler)
            if scan_result.dkim
            else None
        ),
        timestamp=scan_result.timestamp,
        message_timestamp=scan_result.message_timestamp,
    )
