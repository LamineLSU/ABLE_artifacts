rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 00 51 8D B0 ?? }
        $pattern1 = { 8B 45 08 8B 48 10 56 50 E8 ?? ?? ?? ?? }
        $pattern2 = { 8B 06 83 C4 14 52 50 FF D0 }

    condition:
        any of them
}