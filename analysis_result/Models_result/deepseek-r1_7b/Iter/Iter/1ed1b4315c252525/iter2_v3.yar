rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call and jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF 45 ?? ?? ?? }  # Matches a call with displacement
        $pattern1 = { 74 1A ?? ?? ?? ??. }     # Conditional jump near with target
        $pattern2 = { 0F 85 C0 05 5A 8B CE E8 ?? }  # Memory access pattern

    condition:
        any of them
}