rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass rule targeting multiple detection mechanisms"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? }
        $pattern1 = { E8 ??.FC 6A ?? 5A 8B CE ??.E8 ??.85 C0 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ??.?? 85 C0 }

    condition:
        any of them
}