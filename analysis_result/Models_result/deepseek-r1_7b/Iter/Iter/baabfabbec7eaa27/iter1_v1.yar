rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific test and jump sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [85 C0 74 12 6A 5B E8 F0] }
        $pattern1 = { [85 C0 74 12 6A 5B E9 B3] }
        $pattern2 = { [85 C0 74 12 6A 5B E8 B5] }

    condition:
        any of them
}