rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific memory calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? }  # Combines call and nearby instructions
        $pattern1 = { FF7508 ?? ?? ?? ?? ??. }     # Captures displacement call address from another trace
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }  # Combines multiple consecutive instructions

    condition:
        any of them
}