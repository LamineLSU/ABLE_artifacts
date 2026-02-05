rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 ?? 04 ?? 03 6A ?? 5A 8B CE E8 ?? }
        $pattern1 = { 74 1C ?? ?? ?? ?? 8B 40 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 F7 10 00 ?? ?? ?? ?? 6A ?? ?? 5A 8B CE E8 ?? }

    condition:
        any of them
}