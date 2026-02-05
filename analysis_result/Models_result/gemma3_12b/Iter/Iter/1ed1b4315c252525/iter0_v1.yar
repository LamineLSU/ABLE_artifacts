rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Skipping E8C1FFFFFF call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? C1 E8 08 59 FF 75 08 }

    condition:
        any of them
}