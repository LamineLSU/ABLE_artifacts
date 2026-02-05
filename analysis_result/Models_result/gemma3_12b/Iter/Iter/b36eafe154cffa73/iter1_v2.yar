rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 51 C7 45 FC 00 6A 00 6A 40 68 00 30 00 8B 45 08 50 6A 00 }
        $pattern1 = { 50 FF 15 B4 7D 42 00 50 FF 15 5C 7D 42 00 89 45 FC 83 7D FC 00 75 08 }
        $pattern2 = { 6A 00 FF 15 88 7C 42 00 8B E5 5D C3 }

    condition:
        any of them
}