rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns for sandbox detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 E1 A3 ?? 00 41 E1 A4 FF D2 ?? 00 41 E1 A5 ?? }
        $pattern1 = { 00 41 E2 16 8B 55 0C ?? 00 41 E2 17 ?? ?? ?? ?? ?? }
        $pattern2 = { 00 41 E2 1F FF D0 ?? 00 41 E2 20 ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}