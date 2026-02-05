rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule (JZ, TEST, POP)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 0C 8B 45 FC ?? ?? 0F C3 }
        $pattern1 = { E8 F8 0A ?? ?? 8B EC 8E ?? ?? .C 3 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}