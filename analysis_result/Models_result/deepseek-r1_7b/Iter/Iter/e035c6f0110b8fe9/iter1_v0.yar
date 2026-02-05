rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific execution points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? 00 00 01 04 } // From the first trace
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // From another part of the first trace
        $pattern2 = { E8 ?? E8 ?? E8 45 } // A constructed pattern from multiple instructions in the second trace
    condition:
        any of them
}