rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        wildcard: ??,
        count: 0,
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 C4 ?? }
        $pattern2 = { FF 7F 95 FF 00 15 E3 FA 00 6C 0D 01 EB 0B 53 CC }

    condition:
        any of them
}