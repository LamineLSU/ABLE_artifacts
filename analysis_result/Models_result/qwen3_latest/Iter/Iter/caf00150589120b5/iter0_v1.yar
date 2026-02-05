rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 50 E8 ?? ?? ?? ?? 53 }
        $pattern2 = { 33 C9 E8 ?? ?? ?? ?? A1 88 85 02 01 }

    condition:
        any of them
}