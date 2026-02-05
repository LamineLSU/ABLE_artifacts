rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting test+je decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 01 06 61 7A EA EA 01 06 61 7C 01 06 61 90 }
        $pattern1 = { 00 2C 61 7A EA EA 00 2C 61 7C 00 2C 61 90 }
        $pattern2 = { 01 06 45 E5 EB 01 C3 }

    condition:
        any of them
}