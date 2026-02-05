rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C7 04 FF 96 ?? ?? ?? ?? }
        $pattern1 = { 83 C7 08 FF 96 ?? ?? ?? ?? }
        $pattern2 = { 29 F8 01 F0 83 E9 04 AB }

    condition:
        any of them
}