rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX, JE (evasion check)
        $pattern1 = { FF 15 2C A1 FF 00 }         // Call to ExitProcess
        $pattern2 = { 53 6A 40 53 68 40 11 FF 00 }  // Pushes and call sequence

    condition:
        any of them
}