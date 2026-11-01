/* Experimental static hunting rules. NOT signatures for confirmed malware.
   Tune on known-good and known-cluster binaries prior to production use. */
rule HUNT_CookUp_GooPDF_Prep_And_Fin_URI_Strings
{
    meta:
        description = "Hunt for paired preparation/finalization URI markers in installer files"
        author = "Community research / analyst draft"
        confidence = "low-to-medium; broad hunting only"
        date = "2026-11-01"
    strings:
        $prep = "init=prep" ascii wide
        $fin  = "init=fin" ascii wide
        $one  = "appid=" ascii wide
        $two  = "revid=" ascii wide
        $three = "chan=" ascii wide
        $four  = "apiid=" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 200MB and
        $prep and $fin and 1 of ($one,$two,$three,$four)
}

rule HUNT_Installer_Prep_URL_And_Known_Host
{
    meta:
        description = "Hunt for prep URL co-occurring with one known investigated domain"
        confidence = "medium for linkage, NOT for maliciousness"
        date = "2026-11-01"
    strings:
        $prep = "init=prep" ascii wide
        $host1 = "applicensingstudio.com" ascii wide nocase
        $host2 = "setuppdfsoft.com" ascii wide nocase
        $host3 = "cookingsuiteinstaller.com" ascii wide nocase
        $host4 = "reciperoverapp.com" ascii wide nocase
        $host5 = "nomadiccooknow.com" ascii wide nocase
        $host6 = "securedocinstaller.com" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 200MB and
        $prep and 1 of ($host*)
}
