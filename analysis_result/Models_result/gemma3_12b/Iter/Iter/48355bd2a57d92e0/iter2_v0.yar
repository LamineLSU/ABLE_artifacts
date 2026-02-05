rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 74 39 8B 45 C4 }
        $pattern1 = { 00 B7 34 D0 84 C0 74 20 }
        $pattern2 = { 00 B3 A2 B2 83 3E 00 74 14 }

    condition:
        any of them
}