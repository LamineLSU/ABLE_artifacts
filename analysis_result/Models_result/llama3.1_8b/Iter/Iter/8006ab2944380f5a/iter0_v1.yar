rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 06 83 C4 14 52 5E 5D }
        $pattern1 = { E8 ?? ?? ?? ?? 50 51 FF D2 ?? }
        $pattern2 = { 52 C3 ?? ?? 5E 5D }

    condition:
        any of them
}