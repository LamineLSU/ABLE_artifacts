rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 C9 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? }
        $pattern1 = { 83 C4 04 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? }
        $pattern2 = { 53 E8 ?? ?? ?? ?? 33 FF }

    condition:
        all of them
}