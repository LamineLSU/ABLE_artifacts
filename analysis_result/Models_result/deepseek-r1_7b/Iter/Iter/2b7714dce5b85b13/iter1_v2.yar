rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting mid-trace exit decisions and specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 85 F0 FE FF FF }  // TEST EAX followed by JE - mid-trace
        $pattern1 = { B9 B5 FC FF FF 6A 40 11 15 00 }   // Unusual program counter manipulation
        $pattern2 = { C3 C9 E8 4B 17 00 A1 51 50 }    // Another unusual instruction sequence at later mid-trace

    condition:
        (matches $pattern0) || (matches $pattern1) || (matches $pattern2)
}