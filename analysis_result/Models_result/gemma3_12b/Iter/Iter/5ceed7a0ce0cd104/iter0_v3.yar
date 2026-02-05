rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 8B 45 ?? } // Skip FS:[00000030h] memory access
        $pattern1 = { 83 F8 01 74 20 FF 75 08 FF 15 3C F1 42 00 } // Bypass the comparison and subsequent calls
        $pattern2 = { FF 15 A0 F1 42 00 59 FF 75 08 } // Skip the final call before ExitProcess

    condition:
        any of them
}