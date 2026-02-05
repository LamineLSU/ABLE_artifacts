rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? E8 44 09 00 00 CA 00 41 AF 50 }
        $pattern1 = { FF D0 CA EA 5E 5D EB C3 }
        $pattern2 = { 8D B0 74 0C 00 00 EA ED EA 00 00 0C 74 56 50 EA E8 44 09 00 00 CA 00 41 AF 50 }

    condition:
        any of them
}