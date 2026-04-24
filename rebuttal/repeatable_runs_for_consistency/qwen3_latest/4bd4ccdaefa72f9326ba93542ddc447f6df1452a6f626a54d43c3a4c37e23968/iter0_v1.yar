rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 48 83 F8 FF 74 4E }
        $pattern1 = { 48 83 F8 FF 74 4E }
        $pattern2 = { 4C 8D 8D ?? ?? ?? ?? 48 89 9D ?? ?? ?? ?? }

    condition:
        any of them
}