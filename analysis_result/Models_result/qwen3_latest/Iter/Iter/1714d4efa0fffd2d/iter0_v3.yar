rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 ?? }
        $pattern1 = { FF 15 ?? ?? ?? ?? 33 FF }
        $pattern2 = { 8B 4D ?? 83 C4 ?? FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}