rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D C3 } // Pattern for call edx
        $pattern1 = { 8D B0 A0 0C 00 00 56 50 E8 74 0A 00 00 } // Pattern for lea esi
        $pattern2 = { EC 8B 45 08 8B 88 18 0A 00 00 } // Pattern for in al, dx

    condition:
        any of them
}