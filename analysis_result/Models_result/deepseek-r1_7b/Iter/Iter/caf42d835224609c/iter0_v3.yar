rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 02 34 ED 40 5A E8 54 D3 FF FF EA EA DD EB 00 00 0D B4 }
        $pattern1 = { 02 34 ED 96 50 EA } 
        $pattern2 = { 02 34 ED BA 6A 00 00 00 00 00 }
    condition:
        any of them
}