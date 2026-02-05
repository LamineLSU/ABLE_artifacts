rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? A1 ?? A1 ?? }
        $pattern1 = { E8 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C8 C3 ?? A1 8C ?? }
        $pattern2 = { 8B 45 ?? F0 ?? A1 74 07 ?? }

    condition:
        any of them
}