rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B0 A0 0A 00 00 56 50 E8 04 13 00 00 }  // Target lea at 0041E812 - 14 bytes
        $pattern1 = { 56 6A 36 6A 00 51 8D B0 A8 0A 00 00 56 50 E8 04 13 00 00 } // Target the check call - 18 bytes
        $pattern2 = { 8B 55 14 8B 45 10 8B 4D 0C 83 C4 14 52 50 51 FF D2 } // Target the setup for the final call - 18 bytes

    condition:
        any of them
}