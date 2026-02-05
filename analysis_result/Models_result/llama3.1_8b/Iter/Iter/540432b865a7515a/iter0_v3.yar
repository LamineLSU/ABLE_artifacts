rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 53 FF 15 ?? ?? ?? ?? CA 12 20 }
        $pattern2 = { 55 E8 C8 FF FF FF FF }
        $pattern3 = { 50 FF 15 ?? ?? ?? ?? CE 1C 00 }

    condition:
        any of them
}