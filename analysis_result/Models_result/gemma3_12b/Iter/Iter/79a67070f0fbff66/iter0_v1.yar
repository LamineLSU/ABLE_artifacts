rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D C4 3B 4D FC 73 22 }
        $pattern1 = { EB CD 8B 55 E4 52 }
        $pattern2 = { 6A 00 8B 0D 60 42 61 00 }

    condition:
        any of them
}