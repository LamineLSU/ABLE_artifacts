rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Targeting multiple instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? 5C 8B EC FF 83 6C ?? }
        $pattern1 = { 74 ?? 8B 4D ?? ?? ?? 5B ?? 5E ?? ?? ?? 8B 4A ?? }
        $pattern2 = { 0F 84 ?? E8 B9 ?? ?? 5C ?? ?? ?? ?? FF FC ?? }

    condition:
        any of them
}