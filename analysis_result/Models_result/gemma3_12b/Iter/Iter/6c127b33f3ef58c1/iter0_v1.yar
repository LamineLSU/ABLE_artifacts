rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 ?? 74 20 FF 75 ?? FF 15 ?? ?? 42 00 }
        $pattern1 = { A8 01 75 10 FF 75 ?? FF 15 ?? ?? 42 00 }
        $pattern2 = { E8 ?? ?? ?? ?? 83 F8 ?? 74 20 FF 75 ?? }

    condition:
        any of them
}