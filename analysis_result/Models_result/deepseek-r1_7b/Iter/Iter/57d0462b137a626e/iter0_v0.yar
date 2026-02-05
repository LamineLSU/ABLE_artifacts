rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting speculative execution"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 0F 84 3C 3A C0 00 85 C0 0F 84 ?? ?? ?? ?? E9 F5 FC ?? }
        $pattern1 = { 6A 5B 5A 8B CE 8C E8 74 FF 25 ?? ?? ?? ?? 8B 40 0F 84 3C 3A C0 00 }
        $pattern2 = { 6A 40 5A 8B CE 8C E8 74 FF 25 ?? ?? ?? ?? 8B EC 0F 84 3C 3A C0 00 }

    condition:
        any of them
}