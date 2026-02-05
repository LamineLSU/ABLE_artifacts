rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 ?? 8B C0 }
        $pattern1 = { 74 ?? 8B C0 FC 85 C9 }
        $pattern2 = { 85 C9 0B C0 F8 58 85 F6 }

    condition: all of them
}