rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 ?? ?? ?? ?? 74 05 0F ?? }
        $pattern1 = { E9 B5 ?? ?? ?? ?? 74 00 ?? ?? ?? ?? }
        $pattern2 = { E8 C1 ?? ?? ?? ?? 74 0B 0F ?? }

    condition:
        any of them
}