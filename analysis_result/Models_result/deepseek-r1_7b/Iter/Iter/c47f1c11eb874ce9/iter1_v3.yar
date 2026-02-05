rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  # Phase 1: JCB instruction with displacement
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }  # Phase 2: !$E0 with conditional jump
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  # Phase 3: Memory access instruction

    condition:
        any of them
}