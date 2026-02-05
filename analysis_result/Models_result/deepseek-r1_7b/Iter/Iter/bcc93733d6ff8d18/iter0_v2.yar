rule EvasionBypass
{
    meta:
        description = "Evasion bypass detection around ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF ?? ?? ?? ?? 8B 4D ?? }  // Example pattern 1
        $pattern1 = { 6A 5B 5A 8B CE E8 FF ?? ?? ?? ?? 03 C1 ?? }  // Example pattern 2
        $pattern2 = { 8B CE FF 8F 03 C3 53 ?? 68 40 11 FC ?? E8 57 ?? }  // Example pattern 3

    condition:
        any of them
}