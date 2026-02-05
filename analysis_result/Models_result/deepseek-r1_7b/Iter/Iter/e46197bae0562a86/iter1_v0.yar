rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }
        $pattern1 = { 0F C0 ??:??? }
        $pattern2 = { 85 C0 ?? ??? }

    condition:
        any of them
}