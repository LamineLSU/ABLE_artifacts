rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 73 D8 AB 83 E9 01 ?? ?? ?? ?? }
        $pattern1 = { FF 96 2C E0 ?? ?? ?? ?? 8D 5E FC }
        $pattern2 = { 83 C7 04 FF 96 2C E0 ?? ?? ?? ?? }

    condition:
        any of them
}