rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 F8 01 }
        $pattern1 = { 74 ?? 64 A1 30 00 00 00 }
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}