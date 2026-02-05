rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 57 56 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 53 57 57 57 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8B 44 24 0C 3B 44 24 14 72 14 77 0A }

    condition:
        any of them
}