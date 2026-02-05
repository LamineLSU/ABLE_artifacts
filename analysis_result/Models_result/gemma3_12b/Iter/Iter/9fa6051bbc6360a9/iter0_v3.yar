rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }  // Bypass the call eax directly
        $pattern1 = { 8B 45 08 8B 48 10 56 6A 35 6A 00 51 8D B0 74 0C 00 00 56 50 } // Bypass the rol instruction
        $pattern2 = { 0A 04 B6 6F C1 84 81 6A 00 55 8B EC 55 8B EC 8B 45 08 } // Bypass the jnbe instruction

    condition:
        any of them
}