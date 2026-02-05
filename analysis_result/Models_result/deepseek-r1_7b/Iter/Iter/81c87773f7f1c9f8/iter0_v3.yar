rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting different function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 04 05 06 07 }
        $pattern1 = { E9 ?? 08 09 0A 0B }
        $pattern2 = { FC ?? 0C 0D 0E 0F }

    condition:
        any of them
}