rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting various registers and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 5A 8B CE 03 C9 8B E5 }
        $pattern1 = { 6A 5B 5A 8B EC 03 C3 5B 8B 4D }
        $pattern2 = { 03 C9 74 12 5E 03 C1 5A 8B E5 }

    condition:
        (any of the patterns match)
}