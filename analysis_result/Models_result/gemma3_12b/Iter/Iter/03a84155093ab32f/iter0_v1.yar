rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 77 B8 0A 04 B6 ?? ?? ?? ?? }
        $pattern1 = { 8B 06 83 C4 14 52 FF D0 }
        $pattern2 = { AD 77 B8 0A 04 B6 ?? ?? ?? ?? }

    condition:
        any of them
}