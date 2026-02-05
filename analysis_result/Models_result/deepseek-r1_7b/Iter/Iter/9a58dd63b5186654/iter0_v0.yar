rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 0D 38 91 45 00 E8 8D FF 00 00 ?? ?? ?? ?? 8B 4D ?? }
        $pattern1 = { 8B 0D A0 00 45 00 E8 8D FF 00 00 ?? ?? ?? ?? 8B 4A ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}