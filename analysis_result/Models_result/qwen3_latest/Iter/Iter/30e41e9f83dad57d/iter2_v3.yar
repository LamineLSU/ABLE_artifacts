rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 07 57 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 8B 45 ?? E8 ?? ?? ?? ?? }
        $pattern2 = { FF 15 ?? ?? ?? ?? 85 C0 75 07 }

    condition:
        any of them
}