rule Bypass_Sample
{
    meta:
        description = "Evasion bypass targeting OR followed by TEST or JZ"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 5A ?? ?? 45 ?? 3E ?? ?? ?? C0 76 5B }
        $pattern1 = { FF C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}