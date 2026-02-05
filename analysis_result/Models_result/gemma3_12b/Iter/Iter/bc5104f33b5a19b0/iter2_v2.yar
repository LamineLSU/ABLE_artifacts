rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 8D 44 24 18 50 8D 84 24 1C 13 00 00 }
        $pattern1 = { 74 4B FF 15 B0 30 FB 00 85 C0 74 4B }
        $pattern2 = { 8B FF 55 E8 7E 32 00 00 84 C0 74 20 }

    condition:
        any of them
}