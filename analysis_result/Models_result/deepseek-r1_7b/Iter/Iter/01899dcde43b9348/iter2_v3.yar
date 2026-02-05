rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass sample trace 00D061F8 by evading initial checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 85 C0 74 12 E8 25 05 00 00 }
        $pattern1 = { 20 85 C0 74 12 6A 5B ?? }
        $pattern2 = { 20 E9 B5 FC FF FF }

    condition:
        any of them
}