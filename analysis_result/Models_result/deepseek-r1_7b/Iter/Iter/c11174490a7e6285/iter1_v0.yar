rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? FE 47 A5 FA }
        $pattern1 = { 6A 5B ?? 5A E8 B4 FC }
        $pattern2 = { 3D 00 00 00 ?? FE D9 ?? }

    condition:
        any of them
}