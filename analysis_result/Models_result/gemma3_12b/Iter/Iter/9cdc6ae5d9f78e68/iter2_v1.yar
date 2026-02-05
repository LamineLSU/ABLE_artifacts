rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 34 12 CF C3 75 10 }
        $pattern1 = { 26 12 CF C2 83 F8 01 74 20 }
        $pattern2 = { 50 12 CF C4 50 FF 15 }

    condition:
        any of them
}