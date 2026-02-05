rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 52 8B 16 50 50 51 51 FF D2 5E 5D }
        $pattern1 = { 8B 45 08 8B 48 14 56 6A 35 6A 00 51 8D B0 98 0C 00 00 }
        $pattern2 = { 55 8B EC 8B 45 08 8B 88 18 0A 00 00 56 6A 36 6A 00 51 }

    condition:
        any of them
}