rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE }  // TEST EAX + JE + push/pop sequence
        $pattern1 = { 74 07 50 FF 15 2C A1 35 00 }  // JE before ExitProcess call
        $pattern2 = { 85 C0 0F 84 33 FD FF FF }     // TEST EAX + JNE (conditional exit)

    condition:
        any of them
}