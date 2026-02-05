rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 18 61 3A 00 57 }
        $pattern1 = { 8D 4D A0 50 50 E8 3E 61 FE FF }
        $pattern2 = { 68 B8 71 3A 00 8D 4D E8 E8 83 BC FF FF }

    condition:
        any of them
}