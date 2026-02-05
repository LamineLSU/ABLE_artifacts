rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? 74 15 ?? ?? ?? ?? 74 15 }
        $pattern2 = { 8B 4D ?? ?? ?? ?? E8 4B ?? ?? ?? ?? }

    condition:
        any of them
}