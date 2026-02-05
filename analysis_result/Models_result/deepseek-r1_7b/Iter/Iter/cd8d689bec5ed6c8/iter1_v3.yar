rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 }
        $pattern1 = { FF ?? ?? ?? ?? 74 ?? 6A ?? 5A 8B CE E8 ?? ?? ?? }
        $pattern2 = { 8B 45 08 00 00 89 ?? 00 00 FF 15 AC B0 41 }

    condition:
        any of them
}