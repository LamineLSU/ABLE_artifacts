rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 ?? 01 74 20 ?? }
        $pattern1 = { FF 6A ?? 5A 8B CE ?? }
        $pattern2 = { 8B 45 ?? E8 F7 25 ?? }

    condition:
        any of them
}