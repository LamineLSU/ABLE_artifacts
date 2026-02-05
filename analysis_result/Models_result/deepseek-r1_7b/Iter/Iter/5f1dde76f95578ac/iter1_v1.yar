rule Bypass_Sample
{
    meta:
        description = "Evasion bypass exploiting long call offsets"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? 15 AC B0 41 00 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 75 08 ?? ?? ?? 15 AC B0 41 00 }

    condition:
        any of them
}