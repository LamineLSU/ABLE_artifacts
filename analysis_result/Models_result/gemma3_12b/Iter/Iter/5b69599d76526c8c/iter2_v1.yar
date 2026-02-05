rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 00 51 8D B0 A0 0A 00 00 }
        $pattern1 = { E8 24 13 00 00 8B 55 14 8B 45 10 }
        $pattern2 = { 52 8B 16 50 51 FF D2 5E 5D }

    condition:
        any of them
}