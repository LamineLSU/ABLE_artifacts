rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting conditional jumps and calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? 4F 84 ?? E8 25 05 00 00 ?? }
        $pattern1 = { E8 25 05 00 00 ?? 74 12 ?? 00 25 61 90 H ?? }
        $pattern2 = { E9 B5 FC FF FF ?? 53 ?? 00 25 5E 85 H ?? }

    condition:
        any of them
}