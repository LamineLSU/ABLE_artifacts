rule Bypass_Sample
{
    meta:
        description = "Evasion bypass targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A ?? 5B 8B CE E8 25 }
        $pattern1 = { E8 CE 0F 84 74 21 6A ?? 5B 8B CE E8 25 }
        $pattern2 = { 0F 84 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}