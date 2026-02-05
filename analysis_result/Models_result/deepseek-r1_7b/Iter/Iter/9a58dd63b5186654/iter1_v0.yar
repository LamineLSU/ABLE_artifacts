rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 5F ?? ???? 7A ... } // Example pattern with wildcards
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? } // Another distinct instruction sequence
        $pattern2 = { ?? ?? 3C C9 ?? ?? ?? } // Yet another unique context

    condition:
        any of them
}