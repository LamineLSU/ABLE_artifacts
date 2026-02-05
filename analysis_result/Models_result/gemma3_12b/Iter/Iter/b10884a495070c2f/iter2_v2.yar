rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 40 40 00 E8 90 F6 FF FF 8B 45 08 50 53 E8 EC F4 FF FF }
        $pattern1 = { 81 EC C8 02 00 00 B9 B2 00 00 00 BE 28 F8 40 00 8B FC F3 A5 FF D0 }
        $pattern2 = { 55 8B EC 53 56 57 68 BC 18 AB 00 FF 74 24 10 E8 E0 FB FF FF }

    condition:
        any of them
}