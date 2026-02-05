rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? }
        $pattern2 = { E8 57 26 00 00 C3 90 90 90 90 90 90 }

    condition:
        any of them
}