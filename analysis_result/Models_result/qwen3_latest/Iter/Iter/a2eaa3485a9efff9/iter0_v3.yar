rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 6A 00 E8 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? }
        $pattern2 = { FF 25 ?? ?? ?? ?? }

    condition:
        any of them
}