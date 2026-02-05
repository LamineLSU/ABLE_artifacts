rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 03 C1 B9 42 8C 16 00 50 E8 ?? ?? ?? ?? }
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}