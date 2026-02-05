rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 EA 59 00 00 84 C0 }
        $pattern1 = { 74 41 83 EC 1C 8B CC 68 38 2B 47 00 E8 95 65 FF FF }
        $pattern2 = { 68 18 61 46 00 6A 00 FF 15 68 93 45 00 }

    condition:
        any of them
}