rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 74 0C 83 04 00 00 00 ?? 8B 6B 5C 02 89 43 02 ?? 8B 5E 00 00 00 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}