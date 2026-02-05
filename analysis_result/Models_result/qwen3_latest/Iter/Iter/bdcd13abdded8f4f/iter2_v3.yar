rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 60 50 55 55 55 BA 61 55 8B EC 55 8B EC }
        $pattern2 = { 50 50 50 51 51 51 8D B0 74 0C 00 00 E8 44 09 00 00 }

    condition:
        all of them
}