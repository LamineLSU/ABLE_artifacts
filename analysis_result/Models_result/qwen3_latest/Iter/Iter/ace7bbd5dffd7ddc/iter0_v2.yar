rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 83 C4 14 52 FF D0 }
        $pattern1 = { 8B 4D 0C 5A 50 E8 ?? ?? ?? ?? }
        $pattern2 = { 83 C4 14 52 E8 ?? ?? ?? ?? }

    condition:
        all of them
}