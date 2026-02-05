rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 55 8B EC 8B 45 08 56 6A 35 6A 00 51 }
        $pattern2 = { 52 8B 16 50 51 E8 24 13 00 00 CA 00 41 F2 33 }

    condition:
        any of them
}