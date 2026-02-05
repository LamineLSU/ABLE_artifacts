rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }
        $pattern1 = { 6A 35 6A 00 51 8D B0 74 0C 00 00 56 50 E8 44 09 00 00 }
        $pattern2 = { 01 DE 1C CE A3 D6 DB E4 B1 04 89 }

    condition:
        any of them
}