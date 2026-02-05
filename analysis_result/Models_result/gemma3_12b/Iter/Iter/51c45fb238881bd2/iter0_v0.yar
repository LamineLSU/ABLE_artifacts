rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 F2 CF FF FF } // TEST EAX + JNE (from Trace 1 & 2 - Check for zero value)
        $pattern1 = { FF 96 B0 00 00 00 00 } // CALL dword ptr [ESI+0xB0] (from Trace 1 & 2 - Likely a sandbox check)
        $pattern2 = { 83 3D 00 10 49 00 00 00 } // CMP dword ptr [0x491000], 0 (from Trace 3 & 4 - Memory check)

    condition:
        any of them
}