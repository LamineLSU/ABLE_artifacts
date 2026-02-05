rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for memory address checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 40 ?? 5A 8B CE E8 ?? ?? ?? 03 C1 ?? }
        $pattern1 = { BA 04 01 00 00 ?? 03 C1 B9 42 8C 2D 01 ?? ?? ?? ?? }
        $pattern2 = { 68 40 11 2D 01 ?? 5A E8 4B 17 00 00 ?? A1 88 85 2D 01 ?? }
    condition:
        any of them
}