rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? 8B CE ?? }
        $pattern1 = { E8 8F ?? ?? ?? 74 C9 ?? }
        $pattern2 = { FF 1A ?? ?? ?? FF 06 ?? }

    condition:
        any of them
}