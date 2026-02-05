rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 40 40 00 E8 90 F6 FF FF }
        $pattern1 = { 8B 45 08 50 53 E8 EC F4 FF FF }
        $pattern2 = { 83 C4 04 85 C0 75 0E }

    condition:
        any of them
}