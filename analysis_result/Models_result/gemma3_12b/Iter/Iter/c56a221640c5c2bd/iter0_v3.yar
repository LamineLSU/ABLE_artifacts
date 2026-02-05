rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B0 A8 0A 00 00 56 50 E8 04 13 00 }  //8DB0 A8 0A 00 00 56 50 E8 04 13 00
        $pattern1 = { 8D B0 A0 0A 00 00 51 8D B0 A8 0A 00 00 56 50 E8 04 13 00 } //8DB0 A0 0A 00 00 51 8DB0 A8 0A 00 00 56 50 E8 04 13 00
        $pattern2 = { 8B 55 0C 8B 06 83 C4 14 52 50 51 FF D0 }  //8B 55 0C 8B 06 83 C4 14 52 50 51 FF D0

    condition:
        any of them
}