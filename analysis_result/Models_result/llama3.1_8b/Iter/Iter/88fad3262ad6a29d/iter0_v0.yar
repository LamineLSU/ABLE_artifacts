rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 FD AF FF FF 85 C0 74 16 E8 70 84 FF FF 85 C0 74 08 }
        $pattern1 = { 6A 00 FF 15 0C F2 47 00 E8 76 E9 FF FF }
        $pattern2 = { 8B 35 AC F1 47 00 68 E7 03 00 00 FF D6 68 9A 02 00 00 FF D6 }

    condition:
        any of them
}