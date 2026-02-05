rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific test-eax-je and conditional exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 25 00 00 00 00 00 } // Specific test-eax-je sequence
        $pattern1 = { 83 E9 0F 84 FF 26 00 00 00 00 00 } // Another specific conditional exit pattern

    condition:
        any of them
}