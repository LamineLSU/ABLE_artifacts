rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B C0 03 8B EC ?? F8 ?? 2E ?? }
        $pattern1 = { 5A A3 8B 45 ?? EC 6D ?? F8 ?? E0 }
        $pattern2 = { 5A F8 FF EC ?? 1B 47 ?? 9C ?? 6D }

    condition:
        any of them
}