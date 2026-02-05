rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? BE ?? 74 ?? ?? ?? ?? }
        $pattern1 = { 83 ?? B0 CD EB 00 ?? ?? ?? ?? ?? }
        $pattern2 = { E8 ?? BE ?? CA ?? 8B 03 EA DD EB }

    condition:
        any of them
}