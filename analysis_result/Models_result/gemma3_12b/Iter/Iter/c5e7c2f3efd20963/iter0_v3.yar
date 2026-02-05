rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 FF D2 EB 9E 6A 00 6A 04 }
        $pattern1 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 FF 15 5C C2 4C 00 }
        $pattern2 = { 8B 45 F8 50 8B 4D 08 8B 51 48 FF D2 8B 45 F8 8B 4D D0 03 48 28 }

    condition:
        any of them
}