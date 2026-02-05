rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting conditional jumps and memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? ?? ?? }  // Early conditional jump
        $pattern1 = { E8 ?? ?? C0 ?? ?? ?? ?? ?? }   // Later conditional jump and memory access
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }  // Stack manipulation sequence

    condition:
        any of them
}