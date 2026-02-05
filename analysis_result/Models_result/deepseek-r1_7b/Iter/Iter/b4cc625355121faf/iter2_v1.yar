rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 74 1A ?? ?? ?? ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 74 ??: 0C ?? ?? ?? ?? 1B ?? }

    condition:
        any of them
}