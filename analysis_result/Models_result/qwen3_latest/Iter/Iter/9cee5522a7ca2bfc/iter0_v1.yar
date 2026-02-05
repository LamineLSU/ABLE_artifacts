rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 96 ?? ?? ?? ?? 09 C0 74 07 }
        $pattern1 = { FF 96 ?? ?? ?? ?? 85 C0 74 0A }
        $pattern2 = { 6A 04 53 57 FF D5 }

    condition:
        any of them
}