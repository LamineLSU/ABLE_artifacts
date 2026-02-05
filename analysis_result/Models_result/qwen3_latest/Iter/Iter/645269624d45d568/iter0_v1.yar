rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 59 FF 75 08 E8 ?? ?? ?? ?? CC }
        $pattern1 = { A8 01 75 10 FF 75 08 E8 ?? ?? ?? ?? }
        $pattern2 = { 83 F8 01 74 20 64 A1 30 00 00 00 }

    condition:
        any of them
}