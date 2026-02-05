rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific bypass points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? } // Call to E8C8FFFFFF with unknown offset
        $pattern2 = { FF 15 AC B0 04 1E 74 05 F2 } // Unique call from another trace

    condition:
        any of them
}