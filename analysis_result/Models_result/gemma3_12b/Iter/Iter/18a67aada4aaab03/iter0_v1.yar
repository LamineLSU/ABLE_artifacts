rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? 83 F8 01 }
        $pattern1 = { A8 01 75 ?? FF 75 08 FF 15 3C F1 42 00 }
        $pattern2 = { FF 15 40 F1 42 00 50 FF 15 40 F1 42 00 }

    condition:
        any of them
}