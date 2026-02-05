rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC E8 ?? ?? ?? ?? DE 00 00 }
        $pattern1 = { FF D7 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { E8 FA FF FF FF }

    condition:
        any of them
}