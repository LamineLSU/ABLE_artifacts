rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 10 6A 00 }
        $pattern1 = { 83 7D 10 00 75 32 }
        $pattern2 = { FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}