rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }          # 6 bytes: Call with displacement
        $pattern1 = { 74 ?? ???? }              # 6 bytes: Conditional jump and wildcard
        $pattern2 = { 6A ?? 5A 8B CE E8 }      # 9 bytes: Push, pop, and jumps

    condition:
        any of them
}