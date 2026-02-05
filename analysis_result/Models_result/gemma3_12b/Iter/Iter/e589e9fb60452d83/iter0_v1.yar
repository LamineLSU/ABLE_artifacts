rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? }
        $pattern1 = { 00 40 19 E4 00 40 19 E5 83 EC 18 53 56 57 }
        $pattern2 = { 00 40 12 B2 50 FF 15 14 30 40 00 }

    condition:
        any of them
}