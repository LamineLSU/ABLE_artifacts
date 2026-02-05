rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass rule targeting specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { FF 75 08 ?? ??. }
        $pattern1 = { FF 15 3C F1 42 ?? ??? }
        $pattern2 = { FF ???? 08 ?? ??? }

    condition:
        any of them
}