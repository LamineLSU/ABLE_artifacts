rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - testing exit paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 74 1A ?? ?? ?? ?? 8B 45 }  // Around the first exit path
        $pattern1 = { E8 C8 0F 84 ?? ?? ?? ?? 74 3F }  // Another bypass path in the second trace
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // Bypass path near the end of the third trace

    condition:
        any of them
}