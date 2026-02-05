rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific address calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FFFF 03 D9 08 ?? ???45 }
        $pattern1 = { E8 C1 FFFF ?? ???6F ???45 }
        $pattern2 = { E8 C1 FFFF FF ??.93 52 51 ?? }

    condition:
        any of them
}