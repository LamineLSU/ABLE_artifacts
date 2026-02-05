rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 8B F8 50 83 F8 11 74 ?? }
        $pattern1 = { FF 15 ?? ?? ?? ?? 5F 5E 5B C3 }
        $pattern2 = { 85 C0 75 ?? 50 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}