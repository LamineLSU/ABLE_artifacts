rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule combining specific instruction sequences to bypass memory checks.",
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { 85 C0 74 ?? 5A }
        $pattern1 = { E8 ?? 0F 84 ??? 5A }
        $pattern2 = { 6A ?? 5A 8B CE ??.??.}
    condition:
        any()
}