rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=3"

    strings:
        $pattern0 = { 83 C4 14 52 FF D0 }
        $pattern1 = { E8 ?? ?? ?? ?? 8B 4D FC }
        $pattern2 = { 52 E8 ?? ?? ?? ?? }

    condition:
        all of them
}