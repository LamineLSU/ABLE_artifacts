rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 E1 CF }
        $pattern1 = { 00 41 E1 D2 EA }
        $pattern2 = { 00 41 E2 0C AD 56 }
    condition:
        any of them
}