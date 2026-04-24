rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
        $pattern1 = { FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? EB 38 }
        $pattern2 = { 83 7D 10 00 75 32 }

    condition:
        any of them
}