rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting suspicious call patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } (11 bytes)
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } (12 bytes)
        $pattern2 = { ?? ?? B7 28 00 A3 00 ?? ?? ?? F9 43 00 8D 1F 06 } (16 bytes)

    condition:
        any of them
}