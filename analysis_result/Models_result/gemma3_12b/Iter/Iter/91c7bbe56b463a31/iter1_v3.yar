rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 BC 24 50 06 00 00 06 }
        $pattern1 = { 74 4C 8D 8C 24 C8 12 00 00 }
        $pattern2 = { 6A 00 51 53 53 53 }

    condition:
        any of them
}