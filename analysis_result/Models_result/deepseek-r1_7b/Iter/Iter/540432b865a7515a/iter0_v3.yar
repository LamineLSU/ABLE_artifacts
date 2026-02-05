rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific memory calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B ?? 5A 8B CE E8 ?? ?? ?? ?? }  # Includes push ebp and call to E8C4
        $pattern1 = { FF15 AC B0 41 00 }             # Direct call without context (needs adjustment)
        $pattern2 = { E874FAFFFF }                  # Specific call from another trace

    condition:
        any of them
}