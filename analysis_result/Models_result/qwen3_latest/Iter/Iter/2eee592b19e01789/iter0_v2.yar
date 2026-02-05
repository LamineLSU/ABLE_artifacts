rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule for early exit via ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 84 C0 74 11 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 48 8BC8 8BD3 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8BD3 8BCB FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}