rule Bypass_Sample
{
    meta:
        description: "Evasion bypass targeting function calls"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=3"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 }  // Matches the first function call's specific instruction sequence
        $pattern1 = { E8 ?? ?? ?? ?? FF 04 05 00 00 00 }  // Captures a generic function call with displacement
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 8D 8C }  // Matches another specific instruction sequence

    condition:
        any of them
}