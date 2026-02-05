rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 00 00 00 35 8B EC EA DD 8B 45 ?? 00 00 00 36 56 8B 88 14 0A 00 00 EC DD EA 00 00 0A 14 }
        $pattern1 = { E8 ?? ?? ?? ?? 8D 0F 5E 8D B0 7C 0C 00 00 EA ED EA 00 00 0C 7C 8D 0F ?? AD 14 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 8E 44 09 00 00 CA EA }

    condition:
        any of them
}