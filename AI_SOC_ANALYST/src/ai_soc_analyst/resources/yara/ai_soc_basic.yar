/*
  Règles YARA génériques d'AI SOC ANALYST (analyse statique uniquement, aucun fichier n'est exécuté).
  Une correspondance est un INDICE à corroborer, jamais une preuve de malveillance à elle seule.
*/
rule AISOC_PowerShell_Download_Cradle
{
    meta:
        description = "Script ou binaire contenant un téléchargeur PowerShell (IEX + WebClient/DownloadString)"
        mitre = "T1059.001,T1105"
    strings:
        $iex = "IEX" ascii wide nocase
        $iex2 = "Invoke-Expression" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "Net.WebClient" ascii wide nocase
        $dl3 = "DownloadFile" ascii wide nocase
    condition:
        filesize < 20MB and 1 of ($iex*) and 1 of ($dl*)
}

rule AISOC_Encoded_PowerShell
{
    meta:
        description = "Lancement PowerShell avec commande encodée et fenêtre masquée"
        mitre = "T1059.001,T1027"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc = /\s-(e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/ ascii wide nocase
        $hid = /-w(indowstyle)?\s+hidden/ ascii wide nocase
    condition:
        filesize < 20MB and $ps and $enc and $hid
}

rule AISOC_Shadow_Copy_Deletion
{
    meta:
        description = "Commandes de suppression des clichés instantanés / sauvegardes (comportement typique de rançongiciel)"
        mitre = "T1490"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "wmic shadowcopy delete" ascii wide nocase
        $c = "wbadmin delete catalog" ascii wide nocase
        $d = "recoveryenabled no" ascii wide nocase
    condition:
        filesize < 50MB and 2 of them
}

rule AISOC_Credential_Dumping_Strings
{
    meta:
        description = "Chaînes associées aux outils de vol d'identifiants (sekurlsa, lsadump, accès LSASS)"
        mitre = "T1003.001"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "lsadump::sam" ascii wide nocase
        $c = "privilege::debug" ascii wide nocase
        $d = "MiniDumpWriteDump" ascii wide
        $e = "lsass.exe" ascii wide nocase
    condition:
        filesize < 50MB and (2 of ($a, $b, $c) or ($d and $e))
}

rule AISOC_Office_Macro_AutoExec
{
    meta:
        description = "Document Office contenant une macro à exécution automatique et un lanceur de commandes"
        mitre = "T1204.002,T1059.005"
    strings:
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Document_Open" ascii wide nocase
        $auto3 = "Workbook_Open" ascii wide nocase
        $exec1 = "WScript.Shell" ascii wide nocase
        $exec2 = "Shell(" ascii wide nocase
        $exec3 = "CreateObject" ascii wide nocase
    condition:
        filesize < 30MB and 1 of ($auto*) and 1 of ($exec*)
}
