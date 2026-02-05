rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 8B CE E8 ?? ?? }
        $pattern1 = { 6A ?? 5A 8B CE ?? ?? }
        $pattern2 = { 74 ?? 8B EC ?? ?? }

    condition:
        any of them
}