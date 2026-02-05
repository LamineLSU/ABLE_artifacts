rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { EB 09 C7 45 FC 00 00 00 8B 4D FC }
        $pattern1 = { 8B 55 C4 ED DD EB 3C 8B 45 E4 EA DD EB 1C 3B 4D FC EC DD EB 04 }
        $pattern2 = { 83 C4 05 AD 05 E8 EF 9C FF FF CA 00 60 4E 60 }

    condition:
        any of them
}