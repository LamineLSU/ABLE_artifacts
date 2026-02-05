rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }
        $pattern1 = { B9 42 8C D0 00 50 E8 ?? ?? ?? ?? }
        $pattern2 = { A1 88 85 D0 00 E8 ?? ?? ?? ?? }

    condition:
        any of them
}