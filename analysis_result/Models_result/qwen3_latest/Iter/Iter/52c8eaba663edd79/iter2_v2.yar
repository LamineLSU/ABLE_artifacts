rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 04 85 C0 74 ?? }
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? 83 C4 04 }
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? 83 C4 04 }

    condition:
        any of them
}