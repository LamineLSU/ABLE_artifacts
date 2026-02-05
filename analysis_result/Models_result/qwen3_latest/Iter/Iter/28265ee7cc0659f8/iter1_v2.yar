rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 33 C9 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? }
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}