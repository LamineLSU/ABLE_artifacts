rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 01 C2 E8 B5 45 45 43 C0 55 55 54 A5 55 55 55 }
        $pattern2 = { 01 E8 79 C0 55 55 54 B6 55 55 53 F6 }
        $pattern3 = { 01 89 D8 E2 45 45 45 A0 55 55 53 F6 }

    condition:
        any of them
}