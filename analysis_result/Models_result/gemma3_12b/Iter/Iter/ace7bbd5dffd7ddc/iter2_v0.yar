rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 52 8B 16 }
        $pattern1 = { 5E 5D C3 99 D8 43 FC }
        $pattern2 = { 56 6A 35 6A 00 51 8D B0 98 0C 00 00 }

    condition:
        any of them
}