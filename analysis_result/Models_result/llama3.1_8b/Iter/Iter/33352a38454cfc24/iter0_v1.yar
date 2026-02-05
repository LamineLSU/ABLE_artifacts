rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 ?? 01 74 ?? 64 A1 ?? ?? ?? ?? }
        $pattern1 = { 85 C0 75 ?? 64 A1 ?? ?? ?? ?? }
        $pattern2 = { FF 75 ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}