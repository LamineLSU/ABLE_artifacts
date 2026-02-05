rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D }
        $pattern1 = { 55 8B EC 8B 45 08 8B 88 18 0A 00 00 56 6A 36 6A 00 51 8D B0 A0 0C 00 00 56 50 E8 74 0A 00 00 }
        $pattern2 = { 8B 16 50 51 FF D2 5E 5D C3 83 EC 26 44 F6 70 43 }

    condition:
        any of them
}