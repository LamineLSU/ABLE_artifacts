rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting common check points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 03 9F 93 B7 03 9F 93 B9 }
        $pattern1 = { 03 9F 93 DE 03 9F 93 DF }
        $pattern2 = { 03 9F 93 F5 03 9F 93 FA }

    condition:
        any of them
}