rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F ?? ?? ?? ?? 8B 45 ?? }   // E8/S0-30h call dword ptr [es:bp+30h]
        $pattern1 = { ?? ?? ?? ?? 8D 82 50 50 50 00 00 00 00 }   // E8/S0-30h call dword ptr [es:bp+30h]
        $pattern2 = { ?? ?? ?? ?? 6A 5F 5C 50 55 54 55 }   // E8/S0-30h call dword ptr [es:bp+30h]

    condition:
        any of them
}

// Bypass point #0 - E8/S0-30h call dword ptr [es:bp+30h]
// This bypass pattern works by skipping the first argument and using wildcard for other address bytes

// Bypass point #1 - E8/S0-30h call dword ptr [es:bp+30h]
// This bypass pattern is more specific but still general enough to work against most evasions

// Bypass point #2 - E8/S0-30h call dword ptr [es:bp+30h]
// This bypass pattern targets the same instruction set with slightly different register usage