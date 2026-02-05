rule EvasionBypass
{
    meta:
        description = "Evasion bypass detection rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 ?? 0C ?? 8B 4D ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? 85 C0 ?? }
        $pattern2 = { 0F ?? C9 0F 84 ?? ?? ?? ?? 8B CE ?? }

    condition:
        any of them
}