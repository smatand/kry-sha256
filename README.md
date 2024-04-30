# KRY Projekt 2
**Autor:** Andrej Smatana

## Popis
Implementacia druheho projektu kurzu Kryptografia. V ramci projektu som vytvoril program pre vypocet SHA-256 kryptografickeho hashu, vypocet MAC spravy za pomoci `SHA(heslo + sprava)` postupu, verifikaciu MAC spravy formou porovnavania dodanej MAC spravy s vypocitanou novou MAC spravou (heslo, vstupna sprava je dodana v prikazovom riadku). 

Na zaver, program umoznuje vykonat length extension utok na MAC. Ten je vykonany za pomoci prepinaca `-e`, s ktorym program zobrazi na vystup novo vypocitanu MAC spravu a na druhom riadku je zobrazena predlzena sprava aj s prikladnym paddingom. Upozornujem, ze v tomto paddingu nie je zobrazene heslo, avsak padding v poslednych 64 bitoch rata s velkostou vstupu, v ktorom to heslo je. Pre nase ucely je ta velkost vzdy vypocitana ako **dlzka spravy + dlzka hesla dodana v argumente**, tzv. treba to brat ako simulaciu.

## Poziadavky
- verziu C++17 minimalne na masine *(testovane na g++ (SUSE Linux) 7.5.0)*

## Pouzitie
Program bez argumentov vypise priklady pouzitia `./kry`:
```bash
$ ./kry
Usage: ./kry [-c (stdin)] [-s (stdin) -k <password>] [-v (stdin) -k <password> -m <mac_to_verify>] [-e (stdin) -n <len_of_password> -m <mac_to_attack> -a <appended_msg>]
Note:   (stdin) is the input message
````

Nasledujuce argumenty maju takyto ucel:
- `-c` - vypocita SHA-256 hash zo spravy v `stdin`
- `-s` - vypocita MAC, je potrebny aj prepinac `-k <HESLO>` pre heslo
- `-v` - verifikuje MAC z `-m <MAC>` s MAC spravou, ktora je vypocitana zo zadanej spravy v `stdin` a hesla `-k <HESLO>`
- `-e` - vykona length extension utok na MAC a vstupnu spravu, povinne su argumenty `-m <MAC>`, `-n <DLZKA_HESLA>` a `-a <DOPLNUJUCA_SPRAVA>`

*Poznamka: vsetky dodatocne argumenty su povinne, inak program konci navratovou chybou `1`*