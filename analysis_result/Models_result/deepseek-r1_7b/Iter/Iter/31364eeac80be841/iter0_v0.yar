rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {E8 ?? ?? ?? ?? 74 ??}
        $pattern1 = {E8 FC ?? ?? ?? ????} // Assuming FC is the displacement from trace
        $pattern2 = {6A ?? 5A 8B CE E8 ?? ?? ?? ??}

    condition:
        any of them
}