rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - TEST EAX with conditional jump"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF C8 FF FF FF FF }  // TEST EAX followed by JG to ExitProcess at 0x40E7C3h
        $pattern1 = { 8B 45 FC FF C8 FF FF FF FF }       // TEST EAX followed by JE to ExitProcess at 0x40E7FFh
        $pattern2 = { 8B 45 FC FF 15 AC B0 41 00 }    // Another possible conditional jump pattern

    condition:
        any of them
}