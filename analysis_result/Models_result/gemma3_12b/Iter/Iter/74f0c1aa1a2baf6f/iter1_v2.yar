rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 65 E8 00 8D 45 BC }
        $pattern1 = { 3C 22 74 11 8D 41 01 }
        $pattern2 = { 83 65 E8 00 50 FF 15 }

    condition:
        any of them
}